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

# Rewritten by scripts/build-standalone.py. Printed in the header so you can
# always tell WHICH copy just ran -- the repo one or a standalone build that
# may be carrying stale config.
BUILD_KIND = "repo checkout"

OK, BAD, WARN = "  [ok]  ", "  [FAIL]", "  [warn]"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--team", required=True)
    ap.add_argument("--as", dest="role", choices=("onboarder", "consumer"),
                    default="onboarder",
                    help="Which identity's credentials are in the environment. "
                         "onboarder = the pipeline's service account, needs "
                         "management rights. consumer = a team's account, which "
                         "MUST NOT have them.")
    ap.add_argument("--base-url", default=os.environ.get("PS_BASE_URL", DEFAULT_BASE))
    args = ap.parse_args()

    cfg = json.loads((REPO / "config" / f"{args.team}.json").read_text())
    ps_cfg = cfg["passwordSafe"]

    client_id = os.environ.get("PS_CLIENT_ID")
    client_secret = os.environ.get("PS_CLIENT_SECRET")
    if not (client_id and client_secret):
        sys.exit("set PS_CLIENT_ID and PS_CLIENT_SECRET")

    failures = 0
    onboarder = args.role == "onboarder"
    print(f"Password Safe preflight - team {args.team}, as {args.role.upper()}"
          f"\n  {args.base_url}"
          f"\n  build: {BUILD_KIND}   file: {pathlib.Path(__file__).name}\n")

    client = PasswordSafeClient(args.base_url, client_id, client_secret)

    # 1. auth
    try:
        user = client.sign_in()
        username = (user or {}).get("UserName")
        print(f"{OK} OAuth + SignAppin as {username}")
    except PasswordSafeError as exc:
        print(f"{BAD} authentication failed: {exc}")
        return 1

    try:
        # ---------------------------------------------------------------- #
        # CONSUMER: the whole point is that it CANNOT see the estate. Here
        # a 403 is a pass and broad visibility is the failure -- the checks
        # are inverted relative to the onboarder.
        # ---------------------------------------------------------------- #
        if not onboarder:
            print(f"\n  a team account should be able to see its own Smart "
                  f"Rules and nothing else.\n")

            for key in ("smartRuleSystems", "smartRuleAccounts"):
                title = ps_cfg[key]
                rule = client.find_smart_rule(title)
                if rule:
                    print(f"{OK} sees own smart rule {title} "
                          f"(id={rule['SmartRuleID']})")
                else:
                    failures += 1
                    print(f"{BAD} cannot see {title!r} - this team will never "
                          f"see its own hosts")

            # Reading these means it holds a global management feature.
            for path, feature in (
                    ("/Workgroups", "AssetManagement.Read"),
                    ("/ManagedSystems", "Password Safe System Management"),
                    ("/FunctionalAccounts", "Password Safe Account Management")):
                try:
                    client.call("GET", path)
                    failures += 1
                    print(f"{BAD} CAN read {path} - it should not. Remove "
                          f"{feature} from this user's group; that feature is "
                          f"global and lets this team see the other team's "
                          f"estate.")
                except PasswordSafeError as exc:
                    if exc.status == 403:
                        print(f"{OK} correctly denied {path} (403)")
                    else:
                        print(f"{WARN} {path} returned {exc.status}, expected 403")

            try:
                accounts = client.call("GET", "/ManagedAccounts") or []
                names = sorted({a.get("SystemName", "?") for a in accounts})
                print(f"{OK} sees {len(accounts)} managed account(s) via its "
                      f"Smart Rules")
                if names:
                    print(f"       systems: {', '.join(names[:8])}"
                          f"{' ...' if len(names) > 8 else ''}")
                    print(f"       ^ confirm none of these belong to another team")
            except PasswordSafeError as exc:
                if exc.status == 403:
                    print(f"{WARN} cannot list /ManagedAccounts (403) - the "
                          f"Requestor role may be missing on its Smart Rules, "
                          f"or no accounts are onboarded yet")
                else:
                    print(f"{WARN} /ManagedAccounts: {exc}")

            return finish(failures, args.role)

        # ---------------------------------------------------------------- #
        # ONBOARDER: needs the management features the consumer must not have.
        # ---------------------------------------------------------------- #
        # 2. workgroup
        try:
            wg = client.get_workgroup(ps_cfg["workgroupName"])
            wg_id = wg.get("ID") or wg.get("WorkgroupID")
            print(f"{OK} workgroup {ps_cfg['workgroupName']} (id={wg_id})")
        except PasswordSafeError as exc:
            failures += 1
            if exc.status == 403:
                print(f"{BAD} cannot read workgroups (403). Needs "
                      f"AssetManagement.Read or ScanManagement.ReadWrite.")
                print(f"       If {username!r} is a TEAM account, this is "
                      f"correct behaviour - rerun with the onboarder's "
                      f"credentials, or --as consumer.")
            else:
                print(f"{BAD} workgroup {ps_cfg['workgroupName']!r}: {exc}")

        # 3. platform
        pid = None
        try:
            pid = client.get_platform_id(ps_cfg.get("platformName", "Linux"))
            print(f"{OK} platform {ps_cfg.get('platformName')} (id={pid})")
        except PasswordSafeError as exc:
            failures += 1
            print(f"{BAD} {exc}")

        # 3b. functional account - MANDATORY when AutoManagementFlag is true.
        try:
            fid = client.get_functional_account_id(
                ps_cfg["functionalAccountName"], pid)
            print(f"{OK} functional account {ps_cfg['functionalAccountName']} "
                  f"(id={fid})")
        except PasswordSafeError as exc:
            failures += 1
            if exc.status == 403:
                print(f"{BAD} cannot read /FunctionalAccounts (403). Needs "
                      f"PasswordSafeAccountManagement.Read or "
                      f"PasswordSafeConfigurationManagement.Read.")
            else:
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
        #
        # GET /SmartRules appears to return only rules the CALLING identity
        # has an assigned role on, not every rule that exists tenant-wide.
        # A rule can be entirely real and still come back empty here if
        # nobody has granted this group a role on it -- so "not found" from
        # this call must NOT be read as "does not exist", or you risk
        # creating a duplicate of something that's already there.
        for key in ("smartRuleSystems", "smartRuleAccounts"):
            title = ps_cfg[key]
            rule = client.find_smart_rule(title)
            if rule:
                print(f"{OK} smart rule {title} (id={rule['SmartRuleID']})")
            else:
                failures += 1
                print(f"{BAD} smart rule {title!r} not visible to "
                      f"{username!r}.")
                print(f"       This means ONE of two things -- check the "
                      f"BeyondInsight console before creating anything:")
                print(f"         a) it does not exist yet -> create it as a "
                      f"MANAGED ACCOUNT rule, criteria Workgroup = "
                      f"{ps_cfg['workgroupName']}, action 'Manage Account "
                      f"Settings -> API Enabled = on'")
                print(f"         b) it already exists but the group "
                      f"{username!r} belongs to has no role assigned on it "
                      f"-> open the Smart Rule's Permissions tab and add "
                      f"that group with a role, rather than recreating it")

        # 5. scope sanity
        try:
            accounts = client.call("GET", "/ManagedAccounts") or []
            print(f"{OK} onboarder can see {len(accounts)} managed account(s)")
        except PasswordSafeError as exc:
            print(f"{WARN} could not list managed accounts: {exc}")

        # 6. write targets
        #
        # `need` below is OUR GUESS at the required permission, based on the
        # documented API guide -- it is NOT the tenant's actual error text.
        # Lead with the real message; the guess is only a fallback for when
        # the API returns something generic.
        for path, need in (
                ("/ManagedSystems", "Password Safe System Management (Full control)"),
                ("/Workgroups", "AssetManagement.Read")):
            try:
                client.call("GET", path)
                print(f"{OK} onboarder can read {path}")
            except PasswordSafeError as exc:
                failures += 1
                print(f"{BAD} cannot read {path} ({exc.status})")
                print(f"       tenant says: {exc}")
                print(f"       commonly needs: {need} -- but trust the "
                      f"tenant's own message above over this guess")
    finally:
        client.sign_out()

    return finish(failures, args.role)


def finish(failures, role):
    print()
    if failures:
        print(f"{failures} blocking problem(s) for the {role}.")
        if role == "onboarder":
            print("If these are all 403s, you are probably authenticated as a "
                  "TEAM account rather than the pipeline's service account.")
        return 1
    print(f"preflight passed for the {role}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
