"""
Custom Resource: creates the Password Safe functional account entirely from
CloudFormation. No local box, no ssh-keygen, no human running a script.

  1. AWS::EC2::KeyPair generates the RSA key pair (AWS's infrastructure,
     not ours) and auto-stores the private half as an SSM SecureString at
     /ec2/keypair/{KeyPairId}.
  2. This function reads that parameter, derives the public half itself
     (ssh_pubkey.py -- pure arithmetic on an already-generated key, not new
     key generation, so it's safe to do without a crypto library), and:
       - registers the private key as the Password Safe functional account
         (get-or-create, never a duplicate -- see
         PasswordSafeClient.ensure_functional_account)
       - publishes the derived public key to the SSM parameter that
         environment.yaml's user-data and the main registrar's SSM Run
         Command both read from

Delete is intentionally a NO-OP. The functional account is a shared resource
that every team's environments may depend on; deleting it because someone
tore down this one bootstrap stack would break credential rotation on every
still-running instance in both teams. If you genuinely want to decommission
it, do that by hand in BeyondInsight after confirming nothing depends on it.
"""

import json
import logging
import os
import urllib.request

import boto3

import ec2_keypair
from passwordsafe import PasswordSafeClient, PasswordSafeError
from ssh_pubkey import openssh_public_key, KeyParseError

log = logging.getLogger()
log.setLevel(logging.INFO)

ssm = boto3.client("ssm")
secretsmanager = boto3.client("secretsmanager")

PS_BASE_URL = os.environ["PS_BASE_URL"]
PS_SECRET_ARN = os.environ["PS_SECRET_ARN"]


def load_ps_credentials():
    raw = secretsmanager.get_secret_value(SecretId=PS_SECRET_ARN)["SecretString"]
    doc = json.loads(raw)
    return doc["client_id"], doc["client_secret"]


def on_create_or_update(props):
    key_pair_id = props["KeyPairId"]
    account_name = props.get("AccountName", "ps-rotator")
    platform_name = props.get("PlatformName", "Linux")
    elevation = props.get("ElevationCommand", "sudo")
    pubkey_param = props["PublicKeyParamName"]

    private_key = ec2_keypair.read_private_key(ssm, key_pair_id)
    try:
        public_key = openssh_public_key(private_key, comment=account_name)
    except KeyParseError as exc:
        # Fatal and not retryable by changing anything on our side -- the
        # key EC2 handed us genuinely isn't parseable in a shape we expect.
        raise RuntimeError(f"could not derive public key from {key_pair_id}: "
                           f"{exc}") from exc

    client_id, client_secret = load_ps_credentials()
    with PasswordSafeClient(PS_BASE_URL, client_id, client_secret) as ps:
        platform = ps.get_platform(platform_name)
        if not platform.get("DSSFlag"):
            raise RuntimeError(
                f"platform {platform_name!r} does not accept DSS keys "
                f"(DSSFlag is false) -- this platform needs a password-based "
                f"functional account instead, which this Custom Resource "
                f"does not support. See docs/RUNBOOK.md section 1b.")

        functional_account_id = ps.ensure_functional_account(
            platform, account_name,
            private_key=private_key,
            elevation_command=elevation,
            description="ps-ephemeral-ec2 rotation identity "
                        "(created by CloudFormation)",
        )

    ssm.put_parameter(Name=pubkey_param, Value=public_key,
                      Type="String", Overwrite=True,
                      Description="Public half of the Password Safe "
                                  "functional account key. Not a secret. "
                                  "Managed by CloudFormation -- do not edit "
                                  "by hand.")
    log.info("functional account %s ready (id=%s), public key published to %s",
             account_name, functional_account_id, pubkey_param)

    return str(key_pair_id), {
        "FunctionalAccountId": str(functional_account_id),
        "AccountName": account_name,
        "PublicKeyParam": pubkey_param,
    }


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

    try:
        if request_type in ("Create", "Update"):
            physical_id, data = on_create_or_update(props)
            send_response(event, context, "SUCCESS", physical_id, data)
        elif request_type == "Delete":
            log.info("delete is a deliberate no-op -- see module docstring")
            send_response(event, context, "SUCCESS",
                          physical_id or "no-functional-account-bootstrap")
        else:
            raise ValueError(f"unknown RequestType {request_type}")
    except Exception as exc:                       # noqa: BLE001
        log.exception("functional account bootstrap failed")
        send_response(event, context, "FAILED",
                      physical_id or "FAILED", reason=str(exc)[:900])
