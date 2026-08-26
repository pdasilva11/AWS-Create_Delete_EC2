#!/usr/bin/env bash
set -euo pipefail

BUCKET="${1:?usage: package.sh <s3-bucket> [key]}"
KEY="${2:-registrar/registrar.zip}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"

FILES=(handler.py passwordsafe.py functional_bootstrap.py ssh_pubkey.py ec2_keypair.py)

rm -rf "$BUILD" && mkdir -p "$BUILD"
for f in "${FILES[@]}"; do
  cp "$ROOT/registrar/$f" "$BUILD/"
done

( cd "$BUILD" && zip -q -r registrar.zip "${FILES[@]}" )

aws s3 cp "$BUILD/registrar.zip" "s3://${BUCKET}/${KEY}"
echo "uploaded s3://${BUCKET}/${KEY}"
