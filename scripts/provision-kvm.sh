#!/usr/bin/env bash
#
# Creates/updates the "ISAM.WSTrust.Config" environment-scoped KVM entry
# consumed by the ISAM-WSTrust-TokenExchange shared flow (KVM-Get-ISAMConfig
# policy). Requires an OAuth bearer token for the Apigee Management API.
#
# Usage:
#   ORG=my-org ENV=my-env TOKEN=$(gcloud auth print-access-token) \
#     ./scripts/provision-kvm.sh
#
# Edit the CONFIG_JSON block below (or export CONFIG_JSON_FILE=path/to.json)
# before running against a real environment.

set -euo pipefail

: "${ORG:?Set ORG to your Apigee organization}"
: "${ENV:?Set ENV to your Apigee environment}"
: "${TOKEN:?Set TOKEN to a valid Apigee Management API bearer token}"

MAP_NAME="ISAM.WSTrust.Config"
BASE_URL="https://apigee.googleapis.com/v1/organizations/${ORG}/environments/${ENV}/keyvaluemaps"

if [[ -n "${CONFIG_JSON_FILE:-}" ]]; then
    CONFIG_JSON="$(cat "${CONFIG_JSON_FILE}")"
else
    read -r -d '' CONFIG_JSON <<'JSON' || true
{
  "host1": "isam1.internal.example.com",
  "host2": "isam2.internal.example.com",
  "port": "443",
  "scheme": "https",
  "path": "/TrustServer/SecurityTokenService",
  "connectTimeoutMs": "5000",
  "ioTimeoutMs": "10000",
  "appliesTo": "urn:isam:relying-party:my-service",
  "tokenType": "urn:ietf:params:oauth:token-type:jwt",
  "keyType": "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer",
  "requestType": "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue",
  "clientCertHeader": "X-Client-Cert",
  "compressSaml": false,
  "trustedSigningCertThumbprints": ""
}
JSON
fi

# Collapse to a single line so it can be embedded as one KVM entry value.
CONFIG_JSON_COMPACT="$(printf '%s' "${CONFIG_JSON}" | tr -d '\n' | tr -s ' ')"

echo "Ensuring KVM '${MAP_NAME}' exists in ${ORG}/${ENV} ..."
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "${BASE_URL}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"${MAP_NAME}\"}" || true

echo "Writing 'isam.sts.config' entry ..."
# Try create first; if it already exists, fall back to update.
CREATE_STATUS=$(curl -sS -o /tmp/kvm-create-resp.json -w '%{http_code}' -X POST \
    "${BASE_URL}/${MAP_NAME}/entries" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$(python3 -c 'import json,sys; print(json.dumps({"name":"isam.sts.config","value": sys.argv[1]}))' "${CONFIG_JSON_COMPACT}")")

if [[ "${CREATE_STATUS}" == "409" ]]; then
    echo "Entry exists, updating instead ..."
    curl -sS -o /dev/null -w '%{http_code}\n' -X PUT \
        "${BASE_URL}/${MAP_NAME}/entries/isam.sts.config" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$(python3 -c 'import json,sys; print(json.dumps({"name":"isam.sts.config","value": sys.argv[1]}))' "${CONFIG_JSON_COMPACT}")"
else
    echo "Create response status: ${CREATE_STATUS}"
    cat /tmp/kvm-create-resp.json
fi

echo "Done."
