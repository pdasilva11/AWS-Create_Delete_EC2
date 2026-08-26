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
import secrets
import ssl
import string
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger(__name__)

RETRY_STATUS = {429, 500, 502, 503, 504}
MAX_ATTEMPTS = 4
BACKOFF_BASE = 1.5


def _random_password(length=32):
    """
    Used only inside ensure_functional_account, when the platform requires a
    Password on /FunctionalAccounts but the caller only supplied a
    PrivateKey (the SSH-key-only bootstrap path). This value is never the
    account's real authentication path when a DSS key is also attached --
    it exists purely to satisfy Password Safe's schema, is generated fresh
    each call, and is never logged, stored, or returned to the caller.
    """
    alphabet = string.ascii_letters + string.digits + "!@#%^*-_=+"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#%^*-_=+" for c in pwd)):
            return pwd


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
    def __init__(self, base_url, client_id, client_secret, verify_tls=True, timeout=60):
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
        elif method in ("POST", "PUT", "PATCH"):
            # Some endpoints (e.g. /Credentials/Change) 415 on a body-less
            # POST unless Content-Type is present, even though there is no
            # body to describe. Send the header anyway rather than omit it.
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
            except (urllib.error.URLError, TimeoutError) as exc:
                # A read-phase timeout (waiting on the response body) surfaces
                # as a bare TimeoutError, not wrapped in URLError like a
                # connect-phase failure -- without this branch it skips retry
                # entirely and crashes the whole custom resource on one slow
                # response. Treat it exactly like any other transient
                # network failure.
                reason = getattr(exc, "reason", exc)
                last = (0, str(reason))
                if attempt < MAX_ATTEMPTS:
                    delay = BACKOFF_BASE ** attempt
                    log.warning("%s %s -> %s, retry %d in %.1fs",
                                method, url, reason, attempt, delay)
                    time.sleep(delay)
                    continue
                raise PasswordSafeError(method, url, 0, str(reason))
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

        Credential fields are NOT simple alternatives here, unlike managed
        accounts. Per the documented schema for this endpoint specifically:
          - Password is REQUIRED whenever Platform.RequiresSecret is false --
            unconditionally, even if PrivateKey is also supplied.
          - PrivateKey is OPTIONAL, on top of Password, only usable when
            Platform.DSSFlag is true.
          - Secret is required instead of Password when RequiresSecret is
            true.
        (Managed accounts, by contrast, treat Password and PrivateKey as
        mutually exclusive alternatives -- this is a real difference between
        the two endpoints, not a typo.)

        So an SSH-key-only caller (no password supplied) still needs SOME
        password value sent whenever RequiresSecret is false. We generate a
        throwaway one internally rather than push that requirement onto every
        caller -- it is never the account's real authentication path when a
        DSS key is also attached, never logged, and never returned.
        """
        platform_id = platform["PlatformID"]

        try:
            return self.get_functional_account_id(account_name, platform_id)
        except NotFound:
            pass

        requires_secret = bool(platform.get("RequiresSecret"))
        if requires_secret:
            if not secret:
                raise ValueError(
                    f"platform {platform.get('Name')!r} requires Secret to "
                    f"create a functional account (RequiresSecret=true)")
        elif not (private_key or password):
            raise ValueError(
                "ensure_functional_account needs private_key and/or password "
                "to create the account (platform does not require a Secret)")

        body = {
            "PlatformID": platform_id,
            "AccountName": account_name,
            "DisplayName": display_name or account_name,
            "Description": description or "created by ps-ephemeral-ec2 registrar",
        }

        if requires_secret:
            body["Secret"] = secret
        else:
            # Required on this endpoint regardless of whether a PrivateKey is
            # also being sent -- see docstring above.
            body["Password"] = password or _random_password()

        if private_key:
            if not platform.get("DSSFlag"):
                raise ValueError(
                    f"platform {platform.get('Name')!r} does not accept DSS "
                    f"keys (DSSFlag is false) -- cannot attach a PrivateKey "
                    f"to this functional account")
            # The private half never leaves Password Safe, and each instance
            # carries only the public key.
            body["PrivateKey"] = private_key
            if passphrase:
                body["Passphrase"] = passphrase

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

    def get_dss_key_rule_id(self, name=None):
        """
        GET /DSSKeyRules -- the SSH Key Policy a managed system must carry
        for SSH Key auto-management to actually happen. Leave a managed
        system's DSSKeyRuleID at 0/unset and Credentials/Change does not
        error -- it silently rotates the account's PASSWORD instead of its
        SSH key. Password Safe ships one built-in policy unless more have
        been created, so the common case is: call with no name and take
        the only one that comes back.
        """
        rules = self.call("GET", "/DSSKeyRules") or []
        if name:
            for r in rules:
                if r.get("Name", "").lower() == name.lower():
                    return r["DSSKeyRuleID"]
            known = sorted({r.get("Name", "?") for r in rules})
            raise PasswordSafeError("GET", "/DSSKeyRules", 200,
                                    f"no DSS key rule named {name!r}. Available: {known}")
        if not rules:
            raise PasswordSafeError("GET", "/DSSKeyRules", 200,
                                    "no DSS key rules configured on this tenant -- "
                                    "SSH key auto-management cannot work without one")
        if len(rules) > 1:
            log.warning("multiple DSS key rules exist and none was named in "
                        "config -- using the first: %s", rules[0].get("Name"))
        return rules[0]["DSSKeyRuleID"]

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

    def create_managed_account(self, managed_system_id, account_name, cfg,
                               platform=None, password=None, private_key=None,
                               passphrase=None, workgroup_id=None):
        """
        POST /ManagedSystems/{managedSystemID}/ManagedAccounts

        Requires: Password Safe Account Management (Full control).

        Exactly one of password / private_key. Field names below are the
        documented v3.3 schema exactly. Undocumented keys are silently
        ignored by the API, which makes a typo here look like a working call
        that quietly did nothing -- so do not invent fields.

        version=3.3 is what enables WorkgroupID on the account itself.

        private_key is the SSH-key path: pass platform (from get_platform())
        so its DSSFlag / DSSAutoManagementFlag capability can be checked
        before the call, the same way ensure_functional_account gates
        credential type on capability flags. AWS::EC2::KeyPair generates the
        key material the caller hands in here; this method only ever
        transports it, never generates it.
        """
        if bool(password) == bool(private_key):
            raise ValueError("create_managed_account needs exactly one of "
                             "password or private_key")

        body = {
            "AccountName": account_name,
            "Description": cfg.get("description", "ephemeral EC2 local account"),
            "LoginAccountFlag": False,
            # Without this the account is invisible to the API entirely, no
            # matter what the Smart Rule says.
            "ApiEnabled": True,
            "PasswordRuleID": cfg.get("passwordRuleId", 0),
            "ChangeServicesFlag": False,
            "ChangeTasksFlag": False,
            "RestartServicesFlag": False,
            "AutoManagementFlag": True,
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

        if private_key is not None:
            platform = platform or {}
            if not platform.get("DSSFlag"):
                raise ValueError(
                    f"platform {platform.get('Name')!r} does not accept DSS "
                    f"keys (DSSFlag is false) -- cannot create {account_name!r} "
                    f"as an SSH-key managed account on it")
            if not platform.get("DSSAutoManagementFlag"):
                # Not fatal by API rules, but silently means Password Safe
                # will never take over rotating this key after the one we
                # seed it here -- which defeats the point, so fail loudly
                # rather than leave a key that quietly never rotates.
                raise ValueError(
                    f"platform {platform.get('Name')!r} does not support "
                    f"DSSAutoManagementFlag -- Password Safe cannot take "
                    f"over rotating {account_name!r} after this initial key. "
                    f"Check GET /Platforms for this tenant, or see "
                    f"docs/RUNBOOK.md section 1b.")
            body["PrivateKey"] = private_key
            if passphrase:
                body["Passphrase"] = passphrase
            # After this CFN-seeded key, Password Safe generates and installs
            # every key from here on -- same division of labour as the
            # functional account: AWS generates the very first key
            # (AWS::EC2::KeyPair), Password Safe's own vetted rotation
            # generates every key after that, and this codebase never
            # generates key material itself.
            body["DSSAutoManagementFlag"] = True
            body["PasswordFallbackFlag"] = False
        else:
            body["Password"] = password
            body["PasswordFallbackFlag"] = False
            body["DSSAutoManagementFlag"] = False

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
