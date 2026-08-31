#!/usr/bin/env bash
#
# Creates/updates the "ISAM.JSON.Config" environment-scoped KVM entries
# consumed by the ISAM-JSON-TokenExchange shared flow (KVM-Get-ISAMJSONConfig
# policy). Sibling of scripts/provision-kvm.sh for the WS-Trust bundle -- same
# shape, separate KVM map, since the JSON token endpoint may live on a
# different host/port/path than the SOAP one. Requires an OAuth bearer token
# for the Apigee Management API.
#
# Usage:
#   ORG=my-org ENV=my-env TOKEN=$(gcloud auth print-access-token) \
#     ./scripts/provision-kvm-json.sh
#
# Edit the KEYS array below before running against a real environment.

set -euo pipefail

: "${ORG:?Set ORG to your Apigee organization}"
: "${ENV:?Set ENV to your Apigee environment}"
: "${TOKEN:?Set TOKEN to a valid Apigee Management API bearer token}"

MAP_NAME="ISAM.JSON.Config"
BASE_URL="https://apigee.googleapis.com/v1/organizations/${ORG}/environments/${ENV}/keyvaluemaps"

# key -> value. Required: host1, host2, port, scheme, path, appliesTo,
# tokenType, keyType, requestType. Optional (fine to leave blank/omit):
# connectTimeoutMs, ioTimeoutMs, compressSaml, trustedSigningCertThumbprints.
declare -A KEYS=(
  [isam.json.host1]="isam1.internal.example.com"
  [isam.json.host2]="isam2.internal.example.com"
  [isam.json.port]="443"
  [isam.json.scheme]="https"
  [isam.json.path]="/json/token-exchange"
  [isam.json.connectTimeoutMs]="5000"
  [isam.json.ioTimeoutMs]="10000"
  [isam.json.appliesTo]="urn:isam:relying-party:my-service"
  [isam.json.tokenType]="urn:ietf:params:oauth:token-type:jwt"
  [isam.json.keyType]="http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer"
  [isam.json.requestType]="issue"
  [isam.json.compressSaml]="false"
  # Comma-separated SHA-256 thumbprints of ISAM's signing cert(s). Leave empty
  # to skip pinning -- see README "Signature validation & trust".
  [isam.json.trustedSigningCertThumbprints]=""
)

echo "Ensuring KVM '${MAP_NAME}' exists in ${ORG}/${ENV} ..."
curl -sS -o /dev/null -w '%{http_code}\n' -X POST "${BASE_URL}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"${MAP_NAME}\"}" || true

for key in "${!KEYS[@]}"; do
    value="${KEYS[$key]}"
    echo "Writing '${key}' ..."
    body=$(python3 -c 'import json,sys; print(json.dumps({"name": sys.argv[1], "value": sys.argv[2]}))' "${key}" "${value}")

    CREATE_STATUS=$(curl -sS -o /tmp/kvm-create-resp.json -w '%{http_code}' -X POST \
        "${BASE_URL}/${MAP_NAME}/entries" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        -d "${body}")

    if [[ "${CREATE_STATUS}" == "409" ]]; then
        curl -sS -o /dev/null -w '  updated (%{http_code})\n' -X PUT \
            "${BASE_URL}/${MAP_NAME}/entries/${key}" \
            -H "Authorization: Bearer ${TOKEN}" \
            -H "Content-Type: application/json" \
            -d "${body}"
    else
        echo "  created (${CREATE_STATUS})"
    fi
done

echo "Done."
