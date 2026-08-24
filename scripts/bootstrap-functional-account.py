#!/usr/bin/env python3
"""
Bootstrap the Password Safe functional account. Run ONCE per environment.

Replaces the manual BeyondInsight console step. It:

  1. generates an SSH keypair in a temp dir (PEM -- OpenSSH format is not
     accepted as a DSS private key)
  2. creates the functional account in Password Safe via
     POST /FunctionalAccounts, carrying the PRIVATE key
  3. publishes the PUBLIC key to SSM Parameter Store for user-data to install
  4. optionally stores the private key in Secrets Manager so the registrar can
     recreate the account in a fresh tenant without human involvement
  5. shreds both halves from local disk

The private key never touches an EC2 instance and never appears in a template.
Each host carries only the public half, so compromising one yields nothing
replayable anywhere else.

  export PS_CLIENT_ID=... PS_CLIENT_SECRET=...
  python scripts/bootstrap-functional-account.py --team l1

Idempotent: if the account already exists it reports the existing ID and
changes nothing. Use --rotate-key to deliberately replace the keypair.
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "registrar"))

from passwordsafe import (PasswordSafeClient, PasswordSafeError,  # noqa: E402
                          NotFound)

REPO = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_BASE = ("https://pf65f41b.ps.beyondtrustcloud.com"
                "/BeyondTrust/api/public/v3")
DEFAULT_PARAM = "/ps-ephemeral/functional-account/public-key"


def generate_keypair(tmpdir, comment):
    """PEM, not OpenSSH format -- Password Safe rejects the latter."""
    key = pathlib.Path(tmpdir) / "functional"
    # capture_output=True needs Python 3.7+; PIPE/PIPE is the 3.6-compatible
    # form. This script runs on whatever's installed on the operator's box,
    # which for RHEL/CentOS 7 is the system python3.6 -- so target that, not
    # whatever wrote the script.
    subprocess.run(
        ["ssh-keygen", "-t", "rsa", "-b", "4096", "-m", "PEM",
         "-f", str(key), "-N", "", "-C", comment],
        check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return key.read_text(), (key.with_suffix(".pub")).read_text().strip()


def put_public_key(param_name, public_key, region):
    import boto3
    ssm = boto3.client("ssm", region_name=region)
    ssm.put_parameter(Name=param_name, Value=public_key,
                      Type="String", Overwrite=True,
                      Description="Public half of the Password Safe functional "
                                  "account key. Not a secret.")
    print(f"  published public key to SSM parameter {param_name}")


def put_private_key(secret_id, private_key, region):
    import boto3
    sm = boto3.client("secretsmanager", region_name=region)
    payload = json.dumps({"private_key": private_key})
    try:
        sm.put_secret_value(SecretId=secret_id, SecretString=payload)
    except sm.exceptions.ResourceNotFoundException:
        sm.create_secret(Name=secret_id, SecretString=payload,
                         Description="Password Safe functional account private "
                                     "key. Read only by the registrar Lambda.")
    print(f"  stored private key in Secrets Manager as {secret_id}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--team", required=True)
    ap.add_argument("--base-url", default=os.environ.get("PS_BASE_URL", DEFAULT_BASE))
    ap.add_argument("--param-name", default=DEFAULT_PARAM)
    ap.add_argument("--secret-id", default="ps-ephemeral/functional-account",
                    help="Secrets Manager id for the private key. "
                         "Pass --no-store-private to skip.")
    ap.add_argument("--no-store-private", action="store_true")
    ap.add_argument("--region", default=os.environ.get("AWS_REGION", "us-east-1"))
    ap.add_argument("--rotate-key", action="store_true",
                    help="Replace the keypair even if the account exists.")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    cfg = json.loads((REPO / "config" / f"{args.team}.json").read_text())
    ps_cfg = cfg["passwordSafe"]
    name = ps_cfg["functionalAccountName"]
    platform_name = ps_cfg.get("platformName", "Linux")

    client_id = os.environ.get("PS_CLIENT_ID")
    client_secret = os.environ.get("PS_CLIENT_SECRET")
    if not (client_id and client_secret):
        sys.exit("set PS_CLIENT_ID and PS_CLIENT_SECRET (the Onboarder's)")

    print(f"functional account bootstrap\n  account  : {name}\n"
          f"  platform : {platform_name}\n  tenant   : {args.base_url}\n")

    with PasswordSafeClient(args.base_url, client_id, client_secret) as ps:
        platform = ps.get_platform(platform_name)
        print(f"  platform id={platform['PlatformID']} "
              f"DSSFlag={platform.get('DSSFlag')} "
              f"elevation={platform.get('SupportsElevationFlag')}")

        if not platform.get("DSSFlag"):
            print("\n  !! this platform does not accept DSS keys. You will need "
                  "a password-based functional account instead; see "
                  "docs/RUNBOOK.md 1b.")
            return 1

        try:
            existing = ps.get_functional_account_id(name, platform["PlatformID"])
            if not args.rotate_key:
                print(f"\n  functional account already exists (id={existing}). "
                      f"Nothing to do.\n  Use --rotate-key to replace its keypair.")
                return 0
            print(f"\n  account exists (id={existing}); --rotate-key given, "
                  f"generating a replacement")
        except NotFound:
            print("\n  account does not exist yet -- creating")

        if args.dry_run:
            print("  [dry run] stopping before any change")
            return 0

        with tempfile.TemporaryDirectory() as tmp:
            private_key, public_key = generate_keypair(
                tmp, f"password-safe {name}")
            print(f"  generated 4096-bit RSA keypair "
                  f"({len(private_key)} byte private half)")

            try:
                fid = ps.ensure_functional_account(
                    platform, name,
                    private_key=private_key,
                    elevation_command=ps_cfg.get("elevationCommand", "sudo"),
                    description="ps-ephemeral-ec2 rotation identity",
                )
                print(f"  functional account id={fid}")
            except PasswordSafeError as exc:
                print(f"\n  FAILED to create functional account: {exc}",
                      file=sys.stderr)
                print("  needs Password Safe Account Management (Full control) "
                      "or Configuration Management (Full control)",
                      file=sys.stderr)
                return 1

            put_public_key(args.param_name, public_key, args.region)
            if not args.no_store_private:
                put_private_key(args.secret_id, private_key, args.region)
            # tempdir teardown removes both halves from local disk

    print("\ndone. Instances will pick up the public key at next boot; "
          "the registrar converges it on existing hosts at onboard time.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
