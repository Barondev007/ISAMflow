#!/usr/bin/env sh
# Builds SF-Token-Retry.zip in the layout Apigee expects for import:
#   sharedflowbundle/SF-Token-Retry.xml, sharedflowbundle/policies/...,
#   sharedflowbundle/resources/jsc/..., sharedflowbundle/sharedflows/...
set -eu
cd "$(dirname "$0")"
out="$(pwd)/SF-Token-Retry.zip"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/sharedflowbundle"
cp sharedflowbundle/SF-Token-Retry.xml "$tmp/sharedflowbundle/"
cp -R policies resources sharedflows "$tmp/sharedflowbundle/"
rm -f "$out"
(cd "$tmp" && zip -qr "$out" sharedflowbundle)
echo "built $out"
