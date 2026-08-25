"""
Shared helper: read the private key AWS::EC2::KeyPair auto-generates.

When an AWS::EC2::KeyPair resource is created without PublicKeyMaterial, EC2
generates the RSA key pair itself -- using AWS's own infrastructure, not any
code in this repo -- and stores the private half as an SSM SecureString at
/ec2/keypair/{KeyPairId}.

Two callers read from that same parameter shape:
  - functional_bootstrap.py, for the one shared "ps-rotator" functional
    account (infra/functional-account.yaml)
  - handler.py, for each ephemeral instance's own managed account
    (infra/environment.yaml, one AWS::EC2::KeyPair per environment)

so the lookup lives here once rather than being copied twice and drifting.
"""


def read_private_key(ssm_client, key_pair_id):
    """WithDecryption is required -- this is a SecureString -- or you get
    back ciphertext instead of a usable PEM key."""
    name = f"/ec2/keypair/{key_pair_id}"
    resp = ssm_client.get_parameter(Name=name, WithDecryption=True)
    return resp["Parameter"]["Value"]
