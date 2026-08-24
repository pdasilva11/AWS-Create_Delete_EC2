"""
Minimal BeyondTrust Password Safe Cloud API client.

Deliberately stdlib-only (urllib) so the Lambda needs no layer, no vendored
packages and no build step -- the handler zips to a few KB.

Auth model (Password Safe Cloud, OAuth client-credentials):
  1. POST {base}/Auth/connect/token   form-encoded, grant_type=client_credentials
                                      -> access_token
  2. POST {base}/Auth/SignAppin       Bearer <access_token>
                                      -> establishes the API session (cookie)
  3. ... calls ...
  4. POST {base}/Auth/Signout         always, even on failure

The application user behind the client_id must be user type "Application",
tied to an API Registration with an API Access Policy. See docs/RUNBOOK.md.
"""

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

    def __init__(self, method, path, status, body):
        self.status = status
        self.body = body
        super().__init__(f"{method} {path} -> HTTP {status}: {body[:500]}")


class NotFound(PasswordSafeError):
    """404 from the API. Treated as success on the delete path."""


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
    def sign_in(self):
        """OAuth client-credentials token, then SignAppin to open the session."""
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
            # Never echo the payload verbatim -- it can contain the secret.
            raise PasswordSafeError("POST", "/Auth/connect/token", status,
                                    "token request rejected")
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

    def get_platform_id(self, platform_name):
        for p in self.call("GET", "/Platforms") or []:
            if p.get("Name", "").lower() == platform_name.lower():
                return p["PlatformID"]
        raise PasswordSafeError("GET", "/Platforms", 200,
                                f"no platform named {platform_name!r}")

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
        raise PasswordSafeError(
            "GET", "/FunctionalAccounts", 200,
            f"no functional account named {account_name!r}. Available: {known}. "
            f"Create one in BeyondInsight (Configuration > Privileged Access "
            f"Management > Functional Accounts) with credentials that exist on "
            f"the AMI -- see docs/RUNBOOK.md section 1b.")

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
