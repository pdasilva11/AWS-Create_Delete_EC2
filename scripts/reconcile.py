#!/usr/bin/env python3
"""
Converge deployed CloudFormation stacks with the environment manifests
declared in Git, for one team.

  manifest present, stack absent   -> create
  manifest present, stack present  -> update (no-op if nothing changed)
  manifest absent,  stack present  -> DELETE  (this is what deregisters the
                                               Password Safe account)

Run from the repo root. Used by buildspec.yml inside CodeBuild, but it is a
plain script - run it locally against a sandbox account to see the plan.
"""

import argparse
import json
import os
import pathlib
import sys
import time

import boto3
from botocore.exceptions import ClientError, WaiterError

REPO = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = REPO / "infra" / "environment.yaml"

cfn = boto3.client("cloudformation")


def env(name, default=None, required=True):
    val = os.environ.get(name, default)
    if required and not val:
        sys.exit(f"missing required environment variable {name}")
    return val


def declared_envs(team):
    d = REPO / "teams" / team / "envs"
    out = {}
    for f in sorted(d.glob("*.json")):
        m = json.loads(f.read_text())
        name = m.get("envName") or f.stem
        if name != f.stem:
            sys.exit(f"{f}: envName {name!r} must match the filename")
        out[name] = m
    return out


def deployed_stacks(prefix):
    live = {}
    paginator = cfn.get_paginator("list_stacks")
    skip = {"DELETE_COMPLETE"}
    for page in paginator.paginate():
        for s in page["StackSummaries"]:
            if s["StackStatus"] in skip:
                continue
            if s["StackName"].startswith(prefix):
                live[s["StackName"][len(prefix):]] = s["StackName"]
    return live


def wait(stack_name, waiter_name):
    waiter = cfn.get_waiter(waiter_name)
    try:
        waiter.wait(StackName=stack_name,
                    WaiterConfig={"Delay": 15, "MaxAttempts": 80})
    except WaiterError:
        show_failures(stack_name)
        raise


def show_failures(stack_name):
    """CloudFormation's own error is usually useless; the events are not."""
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except ClientError:
        return
    for e in events[:40]:
        if e.get("ResourceStatus", "").endswith("FAILED"):
            print(f"  !! {e['LogicalResourceId']}: "
                  f"{e.get('ResourceStatusReason','')}", file=sys.stderr)


def deploy(stack_name, manifest, team_cfg, common):
    params = [
        {"ParameterKey": "EnvName", "ParameterValue": manifest["envName"]},
        {"ParameterKey": "TeamConfig",
         "ParameterValue": json.dumps(team_cfg["passwordSafe"] |
                                      {"team": team_cfg["team"]})},
        {"ParameterKey": "RegistrarFunctionArn", "ParameterValue": common["registrar"]},
        {"ParameterKey": "AmiId", "ParameterValue": team_cfg["aws"]["amiId"]},
        {"ParameterKey": "InstanceType",
         "ParameterValue": manifest.get("instanceType",
                                        team_cfg["aws"]["instanceType"])},
        {"ParameterKey": "VpcId", "ParameterValue": common["vpc"]},
        {"ParameterKey": "SubnetId", "ParameterValue": common["subnet"]},
        {"ParameterKey": "ResourceBrokerCidr", "ParameterValue": common["broker_cidr"]},
        {"ParameterKey": "OwnerTag", "ParameterValue": common["owner_tag"]},
        {"ParameterKey": "FunctionalAccountName",
         "ParameterValue": team_cfg["passwordSafe"]["functionalAccountName"]},
        {"ParameterKey": "FunctionalAccountPubKeyParam",
         "ParameterValue": common["pubkey_param"]},
    ]
    tags = [
        {"Key": "Owner", "Value": common["owner_tag"]},
        {"Key": "Team", "Value": team_cfg["team"]},
        {"Key": "Lifecycle", "Value": "ephemeral"},
        {"Key": "ManagedBy", "Value": "ps-ephemeral-ec2"},
        {"Key": "RequestedBy", "Value": manifest.get("requestedBy", "unknown")},
    ]
    body = TEMPLATE.read_text()

    common_args = dict(
        StackName=stack_name,
        TemplateBody=body,
        Parameters=params,
        Tags=tags,
        Capabilities=["CAPABILITY_IAM"],
        RoleARN=common["exec_role"],
    )

    try:
        cfn.describe_stacks(StackName=stack_name)
        exists = True
    except ClientError as exc:
        if "does not exist" not in str(exc):
            raise
        exists = False

    if exists:
        try:
            cfn.update_stack(**common_args)
        except ClientError as exc:
            if "No updates are to be performed" in str(exc):
                print(f"  = {stack_name} already converged")
                return
            raise
        print(f"  ~ updating {stack_name}")
        wait(stack_name, "stack_update_complete")
    else:
        cfn.create_stack(**common_args, OnFailure="DELETE",
                         EnableTerminationProtection=False)
        print(f"  + creating {stack_name}")
        wait(stack_name, "stack_create_complete")

    out = {o["OutputKey"]: o["OutputValue"]
           for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
           .get("Outputs", [])}
    print(f"    instance={out.get('InstanceId')} "
          f"managedAccountId={out.get('ManagedAccountId')} "
          f"workgroup={out.get('Workgroup')}")


def destroy(stack_name, exec_role):
    print(f"  - deleting {stack_name} (deregisters the managed account)")
    cfn.delete_stack(StackName=stack_name, RoleARN=exec_role)
    wait(stack_name, "stack_delete_complete")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--team", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    team_cfg = json.loads((REPO / "config" / f"{args.team}.json").read_text())
    prefix = env("STACK_PREFIX", f"ps-eph-{args.team}-")
    common = {
        "registrar": env("REGISTRAR_ARN"),
        "vpc": env("VPC_ID"),
        "subnet": env("SUBNET_ID"),
        "broker_cidr": env("BROKER_CIDR", "10.0.0.0/16"),
        "owner_tag": env("OWNER_TAG", team_cfg["tags"]["Owner"]),
        "exec_role": env("CFN_EXEC_ROLE"),
        "pubkey_param": env("FUNCTIONAL_ACCOUNT_PUBKEY_PARAM",
                            "/ps-ephemeral/functional-account/public-key"),
    }

    want = declared_envs(args.team)
    have = deployed_stacks(prefix)

    to_create = sorted(set(want) - set(have))
    to_update = sorted(set(want) & set(have))
    to_delete = sorted(set(have) - set(want))

    print(f"team={args.team} declared={len(want)} deployed={len(have)}")
    print(f"  create={to_create} update={to_update} delete={to_delete}")

    if args.dry_run:
        return 0

    failures = []

    # Destroy first: frees names and quota before we ask for more capacity.
    for name in to_delete:
        try:
            destroy(have[name], common["exec_role"])
        except Exception as exc:                    # noqa: BLE001
            failures.append(f"delete {name}: {exc}")

    for name in to_create + to_update:
        try:
            deploy(prefix + name, want[name], team_cfg, common)
        except Exception as exc:                    # noqa: BLE001
            failures.append(f"deploy {name}: {exc}")

    if failures:
        print("\nFAILURES:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1

    print("converged")
    return 0


if __name__ == "__main__":
    sys.exit(main())
