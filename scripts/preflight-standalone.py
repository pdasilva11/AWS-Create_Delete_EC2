# ---------------------------------------------------------------------------
# GENERATED FILE -- do not edit.
# Built by scripts/build-standalone.py from:
#   scripts/preflight.py
#   registrar/passwordsafe.py
# Edit those and rebuild. Self-contained: stdlib only, no repo needed.
# ---------------------------------------------------------------------------
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


# --- inlined: registrar/passwordsafe.py ---

import http.cookiejar
import json
import logging
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger(__name__)

RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 4
BACKOFF_BASE = 1.5


class PasswordSafeError(RuntimeError):
    """Raised for any non-2xx response that survived retries."""

    # Long enough not to clip our own multi-line diagnostics. The cap exists
    # to stop a giant HTML error page flooding a log, not to shorten guidance.
    MAX_BODY = 2000

    def __init__(self, method, path, status, body):
        self.status = status
        self.body = body
        shown = body if len(body) <= self.MAX_BODY else body[:self.MAX_BODY] + " ...[truncated]"
        super().__init__(f"{method} {path} -> HTTP {status}: {shown}")


class NotFound(PasswordSafeError):
    """404 from the API. Treated as success on the delete path."""


class Conflict(PasswordSafeError):
    """409. On create-if-absent paths this means "already there" -- i.e. success."""


class PasswordSafeClient:
    def __init__(self, base_url, client_id, client_secret, verify_tls=True, timeout=30):
        # e.g. https://pf65f41b.ps.beyondtrustcloud.com/BeyondTrust/api/public/v3
        self.base = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self.timeout = timeout
        self._token = None

        ctx = ssl.create_default_context()
        if not verify_tls:
            # Only ever for a private CA during a lab bring-up. Never in prod.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        self._jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self._jar),
        )

    # ------------------------------------------------------------------ #
    # transport
    # ------------------------------------------------------------------ #
    def _raw(self, method, url, data=None, headers=None, form=False):
        body = None
        hdrs = {"Accept": "application/json"}
        if headers:
            hdrs.update(headers)

        if data is not None:
            if form:
                body = urllib.parse.urlencode(data).encode()
                hdrs["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                body = json.dumps(data).encode()
                hdrs["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)

        last = None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                with self._opener.open(req, timeout=self.timeout) as resp:
                    payload = resp.read().decode("utf-8", "replace")
                    return resp.status, payload
            except urllib.error.HTTPError as exc:
                payload = exc.read().decode("utf-8", "replace")
                last = (exc.code, payload)
                if exc.code in RETRY_STATUS and attempt < MAX_ATTEMPTS:
                    delay = BACKOFF_BASE ** attempt
                    log.warning("%s %s -> %s, retry %d in %.1fs",
                                method, url, exc.code, attempt, delay)
                    time.sleep(delay)
                    continue
                return exc.code, payload
            except urllib.error.URLError as exc:
                last = (0, str(exc.reason))
                if attempt < MAX_ATTEMPTS:
                    time.sleep(BACKOFF_BASE ** attempt)
                    continue
                raise PasswordSafeError(method, url, 0, str(exc.reason))
        return last

    def call(self, method, path, data=None, ok=(200, 201, 204), extra_headers=None):
        url = f"{self.base}/{path.lstrip('/')}"
        hdrs = {}
        if self._token:
            hdrs["Authorization"] = f"Bearer {self._token}"
        if extra_headers:
            hdrs.update(extra_headers)

        status, payload = self._raw(method, url, data=data, headers=hdrs)

        if status == 404:
            raise NotFound(method, path, status, payload)
        if status == 409:
            raise Conflict(method, path, status, payload)
        if status not in ok:
            raise PasswordSafeError(method, path, status, payload)

        if not payload.strip():
            return None
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return payload

    # ------------------------------------------------------------------ #
    # session
    # ------------------------------------------------------------------ #
    # RFC 6749 error codes, with what each actually means for Password Safe.
    OAUTH_HINTS = {
        "invalid_client":
            "walk the five setup steps in order -- most failures here are the "
            "third, not a bad secret:\n"
            "          1. API Registration exists, type 'API Access Policy' "
            "(an 'API Key' registration cannot do client_credentials)\n"
            "          2. user exists with user type 'Application'\n"
            "          3. the access policy is ASSIGNED TO THAT USER  <-- "
            "commonly missed; id and secret look fine and still fail\n"
            "          4. client_id / client_secret match that user\n"
            "          5. the user is in a group with API access enabled",
        "unauthorized_client":
            "the application user exists but is not authorised for the "
            "client-credentials grant. Its registration is probably the "
            "'API Key' type rather than 'API Access Policy'.",
        "invalid_grant":
            "the grant was rejected. Usually the secret has expired -- "
            "regenerate it (Users > the app user > Generate OAuth secret).",
        "unsupported_grant_type":
            "the tenant did not accept grant_type=client_credentials.",
        "invalid_request":
            "malformed request -- typically an empty client_id or secret, "
            "which happens when the environment variable did not get set.",
        "invalid_scope":
            "scope rejected; not normally used by Password Safe.",
    }

    def sign_in(self):
        """OAuth client-credentials token, then SignAppin to open the session."""
        # Copy-pasting a secret into `export` very often carries a trailing
        # newline or space. The server then rejects a credential that looks
        # perfectly correct on screen, so say so explicitly.
        for label, value in (("client_id", self._client_id),
                             ("client_secret", self._client_secret)):
            if value != value.strip():
                log.warning("%s has leading/trailing whitespace -- stripping. "
                            "Check how it was exported.", label)
        self._client_id = self._client_id.strip()
        self._client_secret = self._client_secret.strip()

        if not self._client_id or not self._client_secret:
            raise PasswordSafeError("POST", "/Auth/connect/token", 0,
                                    "client_id or client_secret is empty")

        status, payload = self._raw(
            "POST",
            f"{self.base}/Auth/connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            form=True,
        )
        if status != 200:
            # The RESPONSE never contains the secret -- only the request does --
            # so the OAuth error code is safe to surface, and it is the single
            # most useful piece of information when this fails.
            code = desc = None
            try:
                body = json.loads(payload)
                code = body.get("error")
                desc = body.get("error_description")
            except (ValueError, AttributeError):
                pass

            detail = f"OAuth error {code!r}" if code else "no OAuth error code returned"
            if desc:
                detail += f": {desc}"
            hint = self.OAUTH_HINTS.get(code)
            if hint:
                detail += f"\n       -> {hint}"
            detail += (f"\n       (client_id used: {self._client_id[:4]}..."
                       f"{self._client_id[-4:]}, {len(self._client_secret)} "
                       f"char secret)")

            raise PasswordSafeError("POST", "/Auth/connect/token", status, detail)

        self._token = json.loads(payload)["access_token"]

        user = self.call("POST", "/Auth/SignAppin")
        log.info("signed in as %s (userId=%s)",
                 (user or {}).get("UserName"), (user or {}).get("UserId"))
        return user

    def sign_out(self):
        try:
            self.call("POST", "/Auth/Signout")
        except Exception as exc:            # noqa: BLE001 - never mask the real error
            log.warning("sign-out failed (ignored): %s", exc)
        finally:
            self._token = None

    def __enter__(self):
        self.sign_in()
        return self

    def __exit__(self, *exc):
        self.sign_out()
        return False

    # ------------------------------------------------------------------ #
    # lookups
    # ------------------------------------------------------------------ #
    def get_workgroup(self, name):
        return self.call("GET", f"/Workgroups/{urllib.parse.quote(name)}")

    def get_platform(self, platform_name):
        """
        Return the whole platform object, not just the ID. Its capability
        flags (DSSFlag, SupportsElevationFlag, RequiresSecret ...) decide
        which credential fields a functional account is even allowed to carry.
        """
        for p in self.call("GET", "/Platforms") or []:
            if p.get("Name", "").lower() == platform_name.lower():
                return p
        raise PasswordSafeError("GET", "/Platforms", 200,
                                f"no platform named {platform_name!r}")

    def get_platform_id(self, platform_name):
        return self.get_platform(platform_name)["PlatformID"]

    def get_functional_account_id(self, account_name, platform_id=None):
        """
        Password Safe cannot rotate a managed account by itself -- it logs in
        as a FUNCTIONAL account and changes the target account's password from
        there. FunctionalAccountID is REQUIRED on the managed system whenever
        AutoManagementFlag is true, so this must resolve or onboarding fails.

        Requires Password Safe Account Management (Read) or Password Safe
        Configuration Management (Read).
        """
        candidates = self.call("GET", "/FunctionalAccounts") or []
        for a in candidates:
            if a.get("AccountName", "").lower() != account_name.lower():
                continue
            if platform_id is not None and a.get("PlatformID") not in (None, platform_id):
                continue
            return a["FunctionalAccountID"]
        known = sorted({a.get("AccountName", "?") for a in candidates})
        raise NotFound(
            "GET", "/FunctionalAccounts", 404,
            f"no functional account named {account_name!r}. Available: {known}. "
            f"Run scripts/bootstrap-functional-account.py to create it, or see "
            f"docs/RUNBOOK.md section 1b.")

    def ensure_functional_account(self, platform, account_name,
                                  private_key=None, passphrase=None,
                                  password=None, secret=None,
                                  elevation_command="sudo",
                                  display_name=None, description=None):
        """
        POST /FunctionalAccounts -- get-or-create, idempotent.

        Requires: Password Safe Account Management (Full control) OR
                  Password Safe Configuration Management (Full control).

        There is exactly ONE functional account object for the whole fleet;
        every managed system points at it via FunctionalAccountID. So this
        must never create a second one, and three things conspire to prevent
        that: we look first, we let a 409 mean "someone beat us to it", and we
        re-read after a conflict rather than trusting our own write.

        Credential fields are gated on the platform's capability flags. Sending
        PrivateKey to a platform with DSSFlag=false is a 400, and sending a
        Password to one with RequiresSecret=true is a different 400.
        """
        platform_id = platform["PlatformID"]

        try:
            return self.get_functional_account_id(account_name, platform_id)
        except NotFound:
            pass

        if not (private_key or password or secret):
            raise ValueError(
                "ensure_functional_account needs one of private_key, password "
                "or secret to create the account")

        body = {
            "PlatformID": platform_id,
            "AccountName": account_name,
            "DisplayName": display_name or account_name,
            "Description": description or "created by ps-ephemeral-ec2 registrar",
        }

        if platform.get("RequiresSecret") and secret:
            body["Secret"] = secret
        elif private_key and platform.get("DSSFlag"):
            # Preferred: the private half never leaves Password Safe, and each
            # instance carries only the public key.
            body["PrivateKey"] = private_key
            if passphrase:
                body["Passphrase"] = passphrase
        elif password:
            body["Password"] = password
        else:
            raise ValueError(
                f"platform {platform.get('Name')!r} (DSSFlag="
                f"{platform.get('DSSFlag')}, RequiresSecret="
                f"{platform.get('RequiresSecret')}) cannot accept the "
                f"credential type supplied")

        if elevation_command and platform.get("SupportsElevationFlag"):
            body["ElevationCommand"] = elevation_command

        try:
            created = self.call("POST", "/FunctionalAccounts", data=body)
            log.info("created functional account %s (id=%s)", account_name,
                     created.get("FunctionalAccountID"))
            return created["FunctionalAccountID"]
        except Conflict:
            # Another concurrent stack created it between our look and our
            # write. Re-read rather than assuming which of us won.
            log.info("functional account %s already exists (409) -- re-reading",
                     account_name)
            return self.get_functional_account_id(account_name, platform_id)

    def find_smart_rule(self, title):
        for r in self.call("GET", "/SmartRules") or []:
            if r.get("Title", "").lower() == title.lower():
                return r
        return None

    def find_asset(self, workgroup_id, asset_name):
        try:
            return self.call(
                "GET",
                f"/Workgroups/{workgroup_id}/Assets?name="
                f"{urllib.parse.quote(asset_name)}",
            )
        except NotFound:
            return None

    # ------------------------------------------------------------------ #
    # onboarding
    # ------------------------------------------------------------------ #
    def create_managed_system_in_workgroup(self, workgroup_id, platform_id,
                                           functional_account_id,
                                           system_name, ip_address,
                                           dns_name=None, cfg=None):
        """
        POST /Workgroups/{workgroupID}/ManagedSystems

        Creates the managed system directly in the Workgroup. This replaces the
        older two-step "create asset, then attach a managed system to it" dance
        -- one call, and the system lands in the right Workgroup atomically,
        which is what the team's Smart Rule keys on.

        Requires: Password Safe System Management (Full control).

        FunctionalAccountID is mandatory because AutoManagementFlag is true.
        ElevationCommand must be one of sudo|pbrun|pmrun.
        """
        cfg = cfg or {}
        elevation = cfg.get("elevationCommand", "sudo")
        if elevation not in ("sudo", "pbrun", "pmrun", None, ""):
            raise ValueError(f"ElevationCommand must be sudo|pbrun|pmrun, "
                             f"got {elevation!r}")

        body = {
            "EntityTypeID": cfg.get("entityTypeId", 1),   # 1 = Asset
            "WorkgroupID": workgroup_id,
            "SystemName": system_name,
            "HostName": system_name,
            "DnsName": dns_name or system_name,
            "IPAddress": ip_address,
            "PlatformID": platform_id,
            "Port": cfg.get("port", 22),
            "Timeout": cfg.get("timeout", 30),
            "Description": cfg.get("description", "ephemeral EC2"),
            "ContactEmail": cfg.get("contactEmail", ""),
            "PasswordRuleID": cfg.get("passwordRuleId", 0),
            "DSSKeyRuleID": cfg.get("dssKeyRuleId", 0),
            "ReleaseDuration": cfg.get("releaseDuration", 120),
            "MaxReleaseDuration": cfg.get("maxReleaseDuration", 525600),
            "ISAReleaseDuration": cfg.get("isaReleaseDuration", 120),
            "AutoManagementFlag": True,
            "FunctionalAccountID": functional_account_id,
            "ElevationCommand": elevation,
            "SshKeyEnforcementMode": cfg.get("sshKeyEnforcementMode", 0),
            "CheckPasswordFlag": cfg.get("checkPassword", False),
            "ChangePasswordAfterAnyReleaseFlag": cfg.get(
                "changePasswordAfterRelease", True),
            "ResetPasswordOnMismatchFlag": cfg.get("resetOnMismatch", False),
            "ChangeFrequencyType": cfg.get("changeFrequencyType", "first"),
            "ChangeTime": cfg.get("changeTime", "23:30"),
            "AccountNameFormat": 0,
        }
        return self.call("POST", f"/Workgroups/{workgroup_id}/ManagedSystems",
                         data=body)

    def create_managed_account(self, managed_system_id, account_name,
                               password, cfg, workgroup_id=None):
        """
        POST /ManagedSystems/{managedSystemID}/ManagedAccounts

        Requires: Password Safe Account Management (Full control).

        Field names below are the documented v3.3 schema exactly. Undocumented
        keys are silently ignored by the API, which makes a typo here look like
        a working call that quietly did nothing -- so do not invent fields.

        version=3.3 is what enables WorkgroupID on the account itself.
        """
        body = {
            "AccountName": account_name,
            "Password": password,
            "Description": cfg.get("description", "ephemeral EC2 local account"),
            "PasswordFallbackFlag": False,
            "LoginAccountFlag": False,
            # Without this the account is invisible to the API entirely, no
            # matter what the Smart Rule says.
            "ApiEnabled": True,
            "PasswordRuleID": cfg.get("passwordRuleId", 0),
            "ChangeServicesFlag": False,
            "ChangeTasksFlag": False,
            "RestartServicesFlag": False,
            "AutoManagementFlag": True,
            "DSSAutoManagementFlag": False,
            "CheckPasswordFlag": cfg.get("checkPassword", False),
            "ChangePasswordAfterAnyReleaseFlag": cfg.get(
                "changePasswordAfterRelease", True),
            "ResetPasswordOnMismatchFlag": cfg.get("resetOnMismatch", False),
            "ReleaseDuration": cfg.get("releaseDuration", 120),
            "MaxReleaseDuration": cfg.get("maxReleaseDuration", 525600),
            "ISAReleaseDuration": cfg.get("isaReleaseDuration", 120),
            "ChangeFrequencyType": cfg.get("changeFrequencyType", "first"),
            "ChangeTime": cfg.get("changeTime", "23:30"),
            "MaxConcurrentRequests": cfg.get("maxConcurrentRequests", 1),
            "UseOwnCredentials": True,
        }
        if workgroup_id is not None:
            body["WorkgroupID"] = workgroup_id

        return self.call(
            "POST",
            f"/ManagedSystems/{managed_system_id}/ManagedAccounts?version=3.3",
            data=body,
        )

    def rotate_credential(self, managed_account_id, queue=False):
        """
        POST /ManagedAccounts/{managedAccountID}/Credentials/Change

        Forces an immediate password change so the bootstrap value the
        registrar generated is never the live credential.

        This is the call that actually exercises the functional account. If it
        fails with a connection error, the Resource Broker path is wrong -- see
        docs/ARCHITECTURE.md, "Network path".
        """
        suffix = "?queue=true" if queue else ""
        return self.call(
            "POST",
            f"/ManagedAccounts/{managed_account_id}/Credentials/Change{suffix}",
            ok=(200, 202, 204),
        )

    def test_credential(self, managed_account_id):
        """POST /ManagedAccounts/{id}/Credentials/Test -- proves Password Safe
        can actually reach and authenticate to the host."""
        return self.call("POST",
                         f"/ManagedAccounts/{managed_account_id}/Credentials/Test",
                         ok=(200, 202, 204))

    def process_smart_rule(self, smart_rule_id, queue=False):
        """
        Force the Smart Rule to reprocess NOW so the new account is visible to
        the consuming team immediately, instead of at the next scheduled run.
        """
        suffix = "?queue=true" if queue else ""
        return self.call("POST", f"/SmartRules/{smart_rule_id}/Process{suffix}",
                         ok=(200, 202, 204))

    # ------------------------------------------------------------------ #
    # teardown -- every delete is idempotent by design
    # ------------------------------------------------------------------ #
    def delete_managed_account(self, managed_account_id):
        try:
            self.call("DELETE", f"/ManagedAccounts/{managed_account_id}",
                      ok=(200, 204))
            return True
        except NotFound:
            log.info("managed account %s already gone", managed_account_id)
            return False

    def delete_managed_system(self, managed_system_id):
        """
        DELETE /ManagedSystems/{id}

        Removes the system and, with it, the account's home. We delete the
        account first anyway so the teardown reads the same way round as the
        build, and so a partial failure leaves the smaller object orphaned
        rather than the larger one.
        """
        try:
            self.call("DELETE", f"/ManagedSystems/{managed_system_id}",
                      ok=(200, 204))
            return True
        except NotFound:
            log.info("managed system %s already gone", managed_system_id)
            return False

    # ------------------------------------------------------------------ #
    # retrieval -- what the CONSUMER (team) does, not the registrar
    # ------------------------------------------------------------------ #
    def request_credential(self, system_id, account_id, duration_minutes=60,
                           reason="automated retrieval"):
        req = self.call("POST", "/Requests", data={
            "SystemID": system_id,
            "AccountID": account_id,
            "DurationMinutes": duration_minutes,
            "Reason": reason,
            "AccessType": "View",
        })
        request_id = req if isinstance(req, int) else req.get("RequestID")
        secret = self.call("GET", f"/Credentials/{request_id}")
        return request_id, secret

    def checkin(self, request_id, reason="done"):
        self.call("PUT", f"/Requests/{request_id}/Checkin",
                  data={"Reason": reason}, ok=(200, 204))

EMBEDDED_CONFIG = json.loads(r'''
{
    "l1": {
        "team": "l1",
        "teamDisplayName": "DevOps L1",
        "aws": {
            "region": "us-east-1",
            "amiId": "ami-075d73f700ef0e7b3",
            "instanceType": "t3.micro"
        },
        "passwordSafe": {
            "workgroupName": "WG-DevOps-L1",
            "smartRuleSystems": "SR-L1-Systems",
            "smartRuleAccounts": "SR-L1-Accounts",
            "consumerGroup": "GRP-DevOps-L1",
            "localAccountName": "ec2-svc",
            "functionalAccountName": "ps-rotator",
            "platformName": "Linux",
            "port": 22,
            "timeout": 30,
            "elevationCommand": "sudo",
            "sshKeyEnforcementMode": 0,
            "releaseDuration": 120,
            "maxReleaseDuration": 525600,
            "isaReleaseDuration": 120,
            "maxConcurrentRequests": 1,
            "changeFrequencyType": "first",
            "changeTime": "23:30",
            "checkPassword": false,
            "resetOnMismatch": false,
            "changePasswordAfterRelease": true,
            "passwordRuleId": 0
        },
        "tags": {
            "Owner": "DevOpsL1",
            "Lifecycle": "ephemeral",
            "ManagedBy": "ps-ephemeral-ec2"
        }
    },
    "l2": {
        "team": "l2",
        "teamDisplayName": "DevOps L2",
        "aws": {
            "region": "us-east-1",
            "amiId": "ami-075d73f700ef0e7b3",
            "instanceType": "t3.micro"
        },
        "passwordSafe": {
            "workgroupName": "WG-DevOps-L2",
            "smartRuleSystems": "SR-L2-Systems",
            "smartRuleAccounts": "SR-L2-Accounts",
            "consumerGroup": "GRP-DevOps-L2",
            "localAccountName": "ec2-svc",
            "functionalAccountName": "ps-rotator",
            "platformName": "Linux",
            "port": 22,
            "timeout": 30,
            "elevationCommand": "sudo",
            "sshKeyEnforcementMode": 0,
            "releaseDuration": 120,
            "maxReleaseDuration": 525600,
            "isaReleaseDuration": 120,
            "maxConcurrentRequests": 1,
            "changeFrequencyType": "first",
            "changeTime": "23:30",
            "checkPassword": false,
            "resetOnMismatch": false,
            "changePasswordAfterRelease": true,
            "passwordRuleId": 0
        },
        "tags": {
            "Owner": "DevOpsL2",
            "Lifecycle": "ephemeral",
            "ManagedBy": "ps-ephemeral-ec2"
        }
    }
}
''')


def _load_config(team):
    if team not in EMBEDDED_CONFIG:
        raise SystemExit(
            f'unknown team {team!r}. This standalone build knows: '
            f'{sorted(EMBEDDED_CONFIG)}')
    return EMBEDDED_CONFIG[team]

# --- end inlined library ---


DEFAULT_BASE = ("https://pf65f41b.ps.beyondtrustcloud.com"
                "/BeyondTrust/api/public/v3")

# Rewritten by scripts/build-standalone.py. Printed in the header so you can
# always tell WHICH copy just ran -- the repo one or a standalone build that
# may be carrying stale config.
BUILD_KIND = "STANDALONE, built 2026-08-24 18:30"

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

    cfg = _load_config(args.team)
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
        for key in ("smartRuleSystems", "smartRuleAccounts"):
            title = ps_cfg[key]
            rule = client.find_smart_rule(title)
            if rule:
                print(f"{OK} smart rule {title} (id={rule['SmartRuleID']})")
            else:
                failures += 1
                print(f"{BAD} smart rule {title!r} not found. Create it as a "
                      f"MANAGED ACCOUNT rule, criteria Workgroup = "
                      f"{ps_cfg['workgroupName']}, with action "
                      f"'Manage Account Settings -> API Enabled = on'.")

        # 5. scope sanity
        try:
            accounts = client.call("GET", "/ManagedAccounts") or []
            print(f"{OK} onboarder can see {len(accounts)} managed account(s)")
        except PasswordSafeError as exc:
            print(f"{WARN} could not list managed accounts: {exc}")

        # 6. write targets
        for path, need in (
                ("/ManagedSystems", "Password Safe System Management (Full control)"),
                ("/Workgroups", "AssetManagement.Read")):
            try:
                client.call("GET", path)
                print(f"{OK} onboarder can read {path}")
            except PasswordSafeError as exc:
                failures += 1
                print(f"{BAD} cannot read {path} ({exc.status}) - needs {need}")
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
