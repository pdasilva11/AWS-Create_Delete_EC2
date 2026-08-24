#!/usr/bin/env python3
"""
Consumer-side retrieval. This is what a DevOps L1/L2 member (or their runtime
tooling) runs - NOT the registrar. It uses the team's own OAuth application
credentials, which are scoped by Smart Rule and can only see that team's hosts.

  export PS_CLIENT_ID=...        # the TEAM's client, not the onboarder's
  export PS_CLIENT_SECRET=...
  python scripts/fetch-credential.py --account-name ec2-svc --system build-1042

Proves the isolation: run it with L1's client against an L2 host and it should
return nothing at all, not "access denied".
"""

import argparse
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "registrar"))

from passwordsafe import PasswordSafeClient, PasswordSafeError  # noqa: E402

DEFAULT_BASE = ("https://pf65f41b.ps.beyondtrustcloud.com"
                "/BeyondTrust/api/public/v3")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--account-name", default="ec2-svc")
    ap.add_argument("--system", required=True, help="managed system / asset name")
    ap.add_argument("--duration", type=int, default=60, help="minutes")
    ap.add_argument("--reason", default="pipeline retrieval")
    ap.add_argument("--base-url", default=os.environ.get("PS_BASE_URL", DEFAULT_BASE))
    ap.add_argument("--json", action="store_true", help="emit JSON instead of raw secret")
    args = ap.parse_args()

    client_id = os.environ.get("PS_CLIENT_ID")
    client_secret = os.environ.get("PS_CLIENT_SECRET")
    if not (client_id and client_secret):
        sys.exit("set PS_CLIENT_ID and PS_CLIENT_SECRET")

    with PasswordSafeClient(args.base_url, client_id, client_secret) as ps:
        # Only accounts inside this client's Smart Rule scope come back here.
        matches = [
            a for a in (ps.call("GET", "/ManagedAccounts") or [])
            if a.get("AccountName") == args.account_name
            and a.get("SystemName", "").lower() == args.system.lower()
        ]
        if not matches:
            sys.exit(f"no managed account {args.account_name!r} on system "
                     f"{args.system!r} is visible to this client - either it is "
                     f"not onboarded yet, or it belongs to the other team")
        if len(matches) > 1:
            sys.exit(f"ambiguous: {len(matches)} matches")

        acct = matches[0]
        request_id, secret = ps.request_credential(
            acct["SystemId"], acct["AccountId"],
            duration_minutes=args.duration, reason=args.reason)

        try:
            if args.json:
                print(json.dumps({
                    "system": acct.get("SystemName"),
                    "account": acct.get("AccountName"),
                    "requestId": request_id,
                    "password": secret,
                }))
            else:
                # stdout only, never a log line
                print(secret)
        finally:
            # Check in immediately. Holding a request open past its use is how
            # ephemeral infra ends up with long-lived checkouts nobody notices.
            try:
                ps.checkin(request_id, reason="retrieved")
            except PasswordSafeError as exc:
                print(f"warning: check-in failed for request {request_id}: {exc}",
                      file=sys.stderr)


if __name__ == "__main__":
    main()
