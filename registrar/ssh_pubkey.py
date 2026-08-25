"""
Derive an OpenSSH public key from an RSA private key, using nothing but the
stdlib.

Why this exists: AWS::EC2::KeyPair generates the RSA key pair using AWS's own
infrastructure and stores the private half as an SSM SecureString for us --
which is the right way to get a securely-random key, because hand-rolling RSA
key GENERATION (picking large random primes, Miller-Rabin, etc.) is a real
place to introduce a security bug and not something to do in application
code. But EC2 hands back only the private key; it does not separately expose
the public half as a stack attribute. Deriving a public key FROM an
already-generated private key is a different, much safer problem -- it is
pure arithmetic on numbers that already exist, with no randomness and no
security property at stake -- so it is fine to do it ourselves here, in a
few dozen lines, rather than pull in `cryptography` (a compiled C-extension
package that would force a Lambda Layer or container image build step onto
what is otherwise a zero-dependency, zip-and-go function).

EC2's CreateKeyPair documents its PEM output as PKCS#1
("-----BEGIN RSA PRIVATE KEY-----"), which is the same DER shape Password
Safe expects. This parser targets PKCS#1 directly and additionally unwraps a
PKCS#8 envelope if it ever encounters one, since PKCS#8 is just PKCS#1
wrapped in one extra SEQUENCE + OCTET STRING.
"""

import base64
import struct

PKCS1_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
PKCS8_HEADER = "-----BEGIN PRIVATE KEY-----"


class KeyParseError(ValueError):
    pass


def _pem_to_der(pem_text):
    lines = pem_text.strip().splitlines()
    body = "".join(l for l in lines if not l.startswith("-----"))
    try:
        return base64.b64decode(body)
    except Exception as exc:                      # noqa: BLE001
        raise KeyParseError(f"not valid base64 in PEM body: {exc}")


def _read_length(data, idx):
    first = data[idx]
    idx += 1
    if first < 0x80:
        return first, idx
    num_bytes = first & 0x7F
    if num_bytes == 0 or idx + num_bytes > len(data):
        raise KeyParseError("truncated DER length")
    length = int.from_bytes(data[idx:idx + num_bytes], "big")
    return length, idx + num_bytes


def _read_tlv(data, idx):
    if idx >= len(data):
        raise KeyParseError("truncated DER TLV")
    tag = data[idx]
    idx += 1
    length, idx = _read_length(data, idx)
    if idx + length > len(data):
        raise KeyParseError("DER value runs past end of buffer")
    return tag, data[idx:idx + length], idx + length


def _read_sequence_of_integers(seq_bytes):
    ints = []
    idx = 0
    while idx < len(seq_bytes):
        tag, val, idx = _read_tlv(seq_bytes, idx)
        if tag == 0x02:          # INTEGER
            ints.append(int.from_bytes(val, "big"))
        else:
            ints.append(None)    # not an INTEGER; caller decides if it cares
    return ints


def rsa_n_e_from_der(der):
    """
    Returns (n, e) from either a PKCS#1 RSAPrivateKey DER, or a PKCS#8
    PrivateKeyInfo DER wrapping one.

    PKCS#1 RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, d mod(p-1),
    d mod(q-1), qInv }  -- n is the 2nd INTEGER, e is the 3rd.
    """
    outer_tag, outer_val, _ = _read_tlv(der, 0)
    if outer_tag != 0x30:                          # SEQUENCE
        raise KeyParseError(f"expected SEQUENCE, got tag 0x{outer_tag:02x}")

    # Both PKCS#1 and PKCS#8 open with an INTEGER version field, so that
    # alone cannot tell them apart. The SECOND field is the discriminator:
    # PKCS#1's second field is another INTEGER (n). PKCS#8's second field is
    # a SEQUENCE (the AlgorithmIdentifier).
    idx = 0
    tag1, _, idx = _read_tlv(outer_val, idx)
    if tag1 != 0x02:
        raise KeyParseError(f"expected version INTEGER, got tag 0x{tag1:02x}")
    tag2, _, _ = _read_tlv(outer_val, idx)

    if tag2 == 0x02:                                # PKCS#1: rest are INTEGERs
        ints = _read_sequence_of_integers(outer_val)
        if len(ints) < 3 or any(v is None for v in ints[:3]):
            raise KeyParseError("PKCS#1 structure missing n/e")
        return ints[1], ints[2]

    if tag2 == 0x30:                                # PKCS#8: unwrap the OCTET STRING
        idx2 = idx
        tag, _, idx2 = _read_tlv(outer_val, idx2)   # AlgorithmIdentifier, already read above but re-consume
        tag, octet_val, idx2 = _read_tlv(outer_val, idx2)  # PrivateKey OCTET STRING
        if tag != 0x04:
            raise KeyParseError("PKCS#8 PrivateKey field missing")
        inner_tag, inner_val, _ = _read_tlv(octet_val, 0)
        if inner_tag != 0x30:
            raise KeyParseError("PKCS#8 inner key is not a SEQUENCE")
        ints = _read_sequence_of_integers(inner_val)
        if len(ints) < 3 or any(v is None for v in ints[:3]):
            raise KeyParseError("PKCS#8-wrapped PKCS#1 missing n/e")
        return ints[1], ints[2]

    raise KeyParseError(f"unrecognised key structure (second field tag "
                        f"0x{tag2:02x}) -- not PKCS#1 or PKCS#8")


def _ssh_mpint(x):
    """SSH wire-format mpint: length-prefixed, with a leading 0x00 if the
    high bit of the first byte would otherwise be mistaken for a sign bit."""
    if x == 0:
        b = b"\x00"
    else:
        b = x.to_bytes((x.bit_length() + 7) // 8, "big")
        if b[0] & 0x80:
            b = b"\x00" + b
    return struct.pack(">I", len(b)) + b


def _ssh_string(s):
    return struct.pack(">I", len(s)) + s


def openssh_public_key(pem_private_key_text, comment="ps-rotator"):
    """The one function callers actually use."""
    der = _pem_to_der(pem_private_key_text)
    n, e = rsa_n_e_from_der(der)
    blob = _ssh_string(b"ssh-rsa") + _ssh_mpint(e) + _ssh_mpint(n)
    line = "ssh-rsa " + base64.b64encode(blob).decode()
    if comment:
        line += " " + comment
    return line
