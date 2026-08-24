#!/usr/bin/env bash
# Package and upload the registrar. No dependencies to vendor - the client is
# stdlib-only and boto3 ships in the Lambda runtime - so this is just a zip.
set -euo pipefail

BUCKET="${1:?usage: package.sh <s3-bucket> [key]}"
KEY="${2:-registrar/registrar.zip}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"

rm -rf "$BUILD" && mkdir -p "$BUILD"
cp "$ROOT/registrar/handler.py" "$ROOT/registrar/passwordsafe.py" "$BUILD/"

( cd "$BUILD" && zip -q -r registrar.zip handler.py passwordsafe.py )

aws s3 cp "$BUILD/registrar.zip" "s3://${BUCKET}/${KEY}"
echo "uploaded s3://${BUCKET}/${KEY}"
echo
echo "If the registrar stack already exists, force a code refresh with:"
echo "  aws lambda update-function-code --function-name ps-registrar-registrar \\"
echo "    --s3-bucket ${BUCKET} --s3-key ${KEY}"
