#!/usr/bin/env python3
"""
Preflight - validate the Password Safe side BEFORE you wire up any AWS.

Run this first. It authenticates with the OAuth client credentials and checks
that every object the registrar depends on actually exists, with the exact
names in config/<team>.json. Most failures in this design are misnamed
Workgroups or Smart Rules, and this catches them in 5 seconds instead of
during a stack rollback.

  export PS_CLIENT_ID=...
  export PS_CLIENT_SECRET=...
  python scripts/preflight.py --team l1

Nothing is created or modified. Read-only.
"""

import argparse
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "registrar"))

from passwordsafe import PasswordSafeClient, PasswordSafeError  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_BASE = ("https://pf65f41b.ps.beyondtrustcloud.com"
                "/BeyondTrust/api/public/v3")

OK, BAD, WARN = "  [ok]  ", "  [FAIL]", "  [warn]"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--team", required=True)
    ap.add_argument("--base-url", default=os.environ.get("PS_BASE_URL", DEFAULT_BASE))
    args = ap.parse_args()

    cfg = json.loads((REPO / "config" / f"{args.team}.json").read_text())
    ps_cfg = cfg["passwordSafe"]

    client_id = os.environ.get("PS_CLIENT_ID")
    client_secret = os.environ.get("PS_CLIENT_SECRET")
    if not (client_id and client_secret):
        sys.exit("set PS_CLIENT_ID and PS_CLIENT_SECRET")

    failures = 0
    print(f"Password Safe preflight - team {args.team}\n  {args.base_url}\n")

    client = PasswordSafeClient(args.base_url, client_id, client_secret)

    # 1. auth
    try:
        user = client.sign_in()
        print(f"{OK} OAuth + SignAppin as {(user or {}).get('UserName')}")
    except PasswordSafeError as exc:
        print(f"{BAD} authentication failed: {exc}")
        print("       check: application user type, API registration, and that "
              "the client secret has not expired")
        return 1

    try:
        # 2. workgroup
        try:
            wg = client.get_workgroup(ps_cfg["workgroupName"])
            wg_id = wg.get("ID") or wg.get("WorkgroupID")
            print(f"{OK} workgroup {ps_cfg['workgroupName']} (id={wg_id})")
        except PasswordSafeError as exc:
            failures += 1
            print(f"{BAD} workgroup {ps_cfg['workgroupName']!r} not found: {exc}")

        # 3. platform
        pid = None
        try:
            pid = client.get_platform_id(ps_cfg.get("platformName", "Linux"))
            print(f"{OK} platform {ps_cfg.get('platformName')} (id={pid})")
        except PasswordSafeError as exc:
            failures += 1
            print(f"{BAD} {exc}")

        # 3b. functional account - MANDATORY when AutoManagementFlag is true.
        # Missing this is the single most likely cause of a failed onboard.
        try:
            fid = client.get_functional_account_id(
                ps_cfg["functionalAccountName"], pid)
            print(f"{OK} functional account {ps_cfg['functionalAccountName']} "
                  f"(id={fid})")
        except PasswordSafeError as exc:
            failures += 1
            print(f"{BAD} {exc}")
        except KeyError:
            failures += 1
            print(f"{BAD} config/{args.team}.json is missing "
                  f"passwordSafe.functionalAccountName")

        # 3c. elevation command is a closed set in the API
        elev = ps_cfg.get("elevationCommand")
        if elev in ("sudo", "pbrun", "pmrun", None, ""):
            print(f"{OK} elevation command {elev!r}")
        else:
            failures += 1
            print(f"{BAD} elevationCommand must be sudo|pbrun|pmrun, got {elev!r}")

        # 4. smart rules
        for key in ("smartRuleSystems", "smartRuleAccounts"):
            title = ps_cfg[key]
            rule = client.find_smart_rule(title)
            if rule:
                print(f"{OK} smart rule {title} (id={rule['SmartRuleID']})")
            else:
                failures += 1
                print(f"{BAD} smart rule {title!r} not found - the team will "
                      f"never see hosts onboarded by this pipeline")

        # 5. can we actually enumerate anything? confirms scoping is sane
        try:
            accounts = client.call("GET", "/ManagedAccounts") or []
            print(f"{OK} onboarder can see {len(accounts)} managed account(s)")
            if len(accounts) > 200:
                print(f"{WARN} that is a lot - confirm the onboarder is not "
                      f"carrying blanket Account Management rights")
        except PasswordSafeError as exc:
            print(f"{WARN} could not list managed accounts: {exc}")

        # 6. the onboarder needs Full Control to create systems and accounts.
        # Confirm it can at least read the collections it will write to.
        for path, need in (("/ManagedSystems", "Password Safe System Management"),
                           ("/Workgroups", "asset/workgroup read")):
            try:
                client.call("GET", path)
                print(f"{OK} onboarder can read {path}")
            except PasswordSafeError as exc:
                failures += 1
                print(f"{BAD} onboarder cannot read {path} ({exc.status}) - "
                      f"check {need} (Full control)")
    finally:
        client.sign_out()

    print()
    if failures:
        print(f"{failures} blocking problem(s). Fix these before deploying.")
        return 1
    print("preflight passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
