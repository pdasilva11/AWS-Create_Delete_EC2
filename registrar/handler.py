"""
Registrar -- CloudFormation Custom Resource that welds the Password Safe
managed account to the EC2 instance lifecycle.

  Create  -> wait for SSM readiness, set the local account password over SSM
             Run Command, onboard asset + managed system + managed account,
             force an immediate rotation, reprocess both Smart Rules.
  Update  -> rotate + reprocess. Ids are stable.
  Delete  -> delete managed account and asset, reprocess. Idempotent; a
             missing object is success, not failure.

Why the password is set over SSM rather than passed in from CloudFormation:
a CFN parameter is visible in the console, in `describe-stacks`, in the
change set and in CloudTrail. Generating it here means the only copies that
ever exist are in this function's memory and inside Password Safe -- and the
forced rotation at step 6 makes even our copy stale before we return.

DELETE MUST NOT THROW. A Custom Resource that fails on Delete leaves the
stack in DELETE_FAILED and a human has to go clean it up by hand. Every
failure on that path is logged and swallowed; orphan detection is the job of
scripts/reconcile.py, not of stack teardown.
"""

import json
import logging
import os
import secrets
import string
import time
import urllib.request

import boto3

from passwordsafe import PasswordSafeClient, PasswordSafeError

log = logging.getLogger()
log.setLevel(logging.INFO)

ssm = boto3.client("ssm")
secretsmanager = boto3.client("secretsmanager")

PS_BASE_URL = os.environ["PS_BASE_URL"]
PS_SECRET_ARN = os.environ["PS_SECRET_ARN"]

SSM_READY_TIMEOUT = int(os.environ.get("SSM_READY_TIMEOUT", "300"))
SSM_POLL_INTERVAL = 10
CMD_TIMEOUT = 120

CREATE_FAILED_SENTINEL = "CREATE_FAILED"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def load_ps_credentials():
    """Bootstrap secret: the ONLY standing privilege in the whole design."""
    raw = secretsmanager.get_secret_value(SecretId=PS_SECRET_ARN)["SecretString"]
    doc = json.loads(raw)
    return doc["client_id"], doc["client_secret"]


def generate_password(length=32):
    """Avoids shell-hostile characters so the chpasswd heredoc stays safe."""
    alphabet = string.ascii_letters + string.digits + "!@#%^*-_=+"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#%^*-_=+" for c in pwd)):
            return pwd


def wait_for_ssm(instance_id):
    """
    The real readiness gate. DependsOn only tells you the RunInstances API
    returned -- it says nothing about whether the box has booted. If we onboard
    before the host answers, the Password Safe test-connection fails and we
    would hand the team an account they cannot use.
    """
    deadline = time.time() + SSM_READY_TIMEOUT
    while time.time() < deadline:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        info = resp.get("InstanceInformationList", [])
        if info and info[0].get("PingStatus") == "Online":
            log.info("instance %s online in SSM", instance_id)
            return
        time.sleep(SSM_POLL_INTERVAL)
    raise TimeoutError(
        f"{instance_id} did not register with SSM within {SSM_READY_TIMEOUT}s"
    )


def run_command(instance_id, commands):
    cmd = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        TimeoutSeconds=CMD_TIMEOUT,
    )["Command"]["CommandId"]

    deadline = time.time() + CMD_TIMEOUT
    while time.time() < deadline:
        time.sleep(3)
        try:
            inv = ssm.get_command_invocation(
                CommandId=cmd, InstanceId=instance_id
            )
        except ssm.exceptions.InvocationDoesNotExist:
            continue
        if inv["Status"] in ("Success",):
            return inv
        if inv["Status"] in ("Failed", "Cancelled", "TimedOut"):
            # StandardErrorContent is safe to log: the password goes in via
            # stdin heredoc and is never echoed by chpasswd.
            raise RuntimeError(
                f"SSM command {inv['Status']}: {inv.get('StandardErrorContent','')[:500]}"
            )
    raise TimeoutError(f"SSM command {cmd} did not finish in {CMD_TIMEOUT}s")


def provision_local_account(instance_id, username, password):
    """Create (or reset) the local account. Idempotent."""
    script = [
        "set -euo pipefail",
        f"id -u {username} >/dev/null 2>&1 || useradd -m -s /bin/bash {username}",
        f"usermod -aG wheel {username} 2>/dev/null || true",
        # Password auth is required for Password Safe to manage the credential.
        "sed -i 's/^ *PasswordAuthentication .*/PasswordAuthentication yes/' "
        "/etc/ssh/sshd_config",
        "grep -q '^PasswordAuthentication yes' /etc/ssh/sshd_config || "
        "echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config",
        "systemctl restart sshd",
        # heredoc keeps the secret off the process list (no ps(1) exposure)
        "chpasswd <<'EOF'",
        f"{username}:{password}",
        "EOF",
        f"chage -d 0 -M 99999 {username} 2>/dev/null || true",
        f"passwd -u {username} >/dev/null 2>&1 || true",
    ]
    run_command(instance_id, script)
    log.info("local account %s provisioned on %s", username, instance_id)


def reprocess_rules(ps, cfg):
    """Best-effort: a rule that will not reprocess must not fail the stack."""
    for title in (cfg["smartRuleSystems"], cfg["smartRuleAccounts"]):
        try:
            rule = ps.find_smart_rule(title)
            if rule:
                ps.process_smart_rule(rule["SmartRuleID"])
                log.info("reprocessed smart rule %s", title)
            else:
                log.warning("smart rule %r not found -- team will not see this "
                            "host until it exists", title)
        except PasswordSafeError as exc:
            log.warning("smart rule %s reprocess failed: %s", title, exc)


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #
def on_create(props):
    cfg = json.loads(props["Config"]) if isinstance(props["Config"], str) \
        else props["Config"]
    instance_id = props["InstanceId"]
    private_ip = props["PrivateIp"]
    asset_name = props["AssetName"]
    account_name = cfg.get("localAccountName", "ec2-svc")

    wait_for_ssm(instance_id)

    password = generate_password()
    provision_local_account(instance_id, account_name, password)

    client_id, client_secret = load_ps_credentials()
    with PasswordSafeClient(PS_BASE_URL, client_id, client_secret) as ps:
        wg = ps.get_workgroup(cfg["workgroupName"])
        workgroup_id = wg.get("ID") or wg.get("WorkgroupID")
        platform_id = ps.get_platform_id(cfg.get("platformName", "Linux"))

        # Password Safe rotates the managed account by logging in AS the
        # functional account. Mandatory whenever AutoManagementFlag is true.
        functional_account_id = ps.get_functional_account_id(
            cfg["functionalAccountName"], platform_id)

        # One call: the managed system is created directly in the Workgroup,
        # so it can never briefly exist outside the team's Smart Rule scope.
        system = ps.create_managed_system_in_workgroup(
            workgroup_id, platform_id, functional_account_id,
            system_name=asset_name,
            ip_address=private_ip,
            dns_name=props.get("PrivateDnsName") or asset_name,
            cfg=cfg,
        )
        system_id = system["ManagedSystemID"]

        account = ps.create_managed_account(
            system_id, account_name, password, cfg, workgroup_id=workgroup_id)
        account_id = account["ManagedAccountID"]

        # Password Safe now owns the credential. Rotate immediately so the
        # value this function generated is dead before the stack completes.
        # A failure here almost always means the functional account cannot
        # reach the host -- check the Resource Broker path before anything else.
        try:
            ps.rotate_credential(account_id)
        except PasswordSafeError as exc:
            log.warning("INITIAL ROTATION FAILED (%s). The bootstrap password "
                        "is still live. Verify the functional account can "
                        "reach %s on port %s.", exc, private_ip,
                        cfg.get("port", 22))

        reprocess_rules(ps, cfg)

    physical_id = f"{system_id}:{account_id}"
    log.info("onboarded %s as %s", asset_name, physical_id)
    return physical_id, {
        "ManagedSystemId": str(system_id),
        "ManagedAccountId": str(account_id),
        "AccountName": account_name,
        "Workgroup": cfg["workgroupName"],
    }


def on_update(physical_id, props):
    """Ids are stable across updates -- never return a new PhysicalResourceId
    here, or CloudFormation will schedule a Delete on the old one."""
    cfg = json.loads(props["Config"]) if isinstance(props["Config"], str) \
        else props["Config"]
    try:
        _system_id, account_id = physical_id.split(":")
    except ValueError:
        log.warning("unparseable physical id %r on update -- no-op", physical_id)
        return physical_id, {}

    client_id, client_secret = load_ps_credentials()
    with PasswordSafeClient(PS_BASE_URL, client_id, client_secret) as ps:
        try:
            ps.rotate_credential(int(account_id))
        except PasswordSafeError as exc:
            log.warning("rotation on update failed: %s", exc)
        reprocess_rules(ps, cfg)
    return physical_id, {"ManagedAccountId": account_id}


def on_delete(physical_id, props):
    """Never raises. See module docstring."""
    if not physical_id or physical_id.startswith(CREATE_FAILED_SENTINEL):
        log.info("nothing was ever created -- delete is a no-op")
        return

    try:
        system_id, account_id = physical_id.split(":")
    except ValueError:
        log.warning("unparseable physical id %r -- nothing to deregister",
                    physical_id)
        return

    try:
        cfg = json.loads(props["Config"]) if isinstance(props.get("Config"), str) \
            else props.get("Config", {})
        client_id, client_secret = load_ps_credentials()
        with PasswordSafeClient(PS_BASE_URL, client_id, client_secret) as ps:
            # Account first, then its system. Both are idempotent; a 404 on
            # either is treated as already-done.
            ps.delete_managed_account(int(account_id))
            ps.delete_managed_system(int(system_id))
            if cfg:
                reprocess_rules(ps, cfg)
        log.info("deregistered %s", physical_id)
    except Exception as exc:                       # noqa: BLE001 - intentional
        log.error("DEREGISTRATION FAILED for %s: %s -- stack delete will "
                  "continue. Run scripts/reconcile.py to clean up the orphan.",
                  physical_id, exc)


# --------------------------------------------------------------------------- #
# CloudFormation plumbing
# --------------------------------------------------------------------------- #
def send_response(event, context, status, physical_id, data=None, reason=None):
    body = json.dumps({
        "Status": status,
        "Reason": reason or f"See CloudWatch log stream {context.log_stream_name}",
        "PhysicalResourceId": physical_id,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "NoEcho": False,
        "Data": data or {},
    }).encode()

    req = urllib.request.Request(
        event["ResponseURL"], data=body, method="PUT",
        headers={"content-type": "", "content-length": str(len(body))},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        log.info("cfn response %s -> %s", status, resp.status)


def lambda_handler(event, context):
    log.info("request: %s", json.dumps(
        {k: v for k, v in event.items() if k != "ResponseURL"}))

    request_type = event["RequestType"]
    props = event.get("ResourceProperties", {})
    physical_id = event.get("PhysicalResourceId")
    data = {}

    try:
        if request_type == "Create":
            physical_id, data = on_create(props)
        elif request_type == "Update":
            physical_id, data = on_update(physical_id, props)
        elif request_type == "Delete":
            on_delete(physical_id, props)
        else:
            raise ValueError(f"unknown RequestType {request_type}")

        send_response(event, context, "SUCCESS", physical_id, data)

    except Exception as exc:                       # noqa: BLE001
        log.exception("registrar failed")
        if request_type == "Delete":
            # Belt and braces: even an unexpected failure must not wedge the
            # stack in DELETE_FAILED.
            send_response(event, context, "SUCCESS",
                          physical_id or CREATE_FAILED_SENTINEL,
                          reason=f"delete tolerated failure: {exc}")
        else:
            send_response(event, context, "FAILED",
                          physical_id or CREATE_FAILED_SENTINEL,
                          reason=str(exc)[:900])
