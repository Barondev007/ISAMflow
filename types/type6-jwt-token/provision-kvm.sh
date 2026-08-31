#!/usr/bin/env bash
#
# Creates/updates the "ISAM.JwtToken.Config" KVM entries for the
# ISAM-JWT-Token shared flow (type 6: JWT request, JWT-is-the-token
# response -- no compressSaml/trustedSigningCertThumbprints keys, since
# there's no SAML assertion involved anywhere in this type).
#
# Usage:
#   ORG=my-org ENV=my-env TOKEN=$(gcloud auth print-access-token) \
#     ./provision-kvm.sh

set -euo pipefail

: "${ORG:?Set ORG to your Apigee organization}"
: "${ENV:?Set ENV to your Apigee environment}"
: "${TOKEN:?Set TOKEN to a valid Apigee Management API bearer token}"

MAP_NAME="ISAM.JwtToken.Config"
BASE_URL="https://apigee.googleapis.com/v1/organizations/${ORG}/environments/${ENV}/keyvaluemaps"

declare -A KEYS=(
  [isam.jwttoken.host1]="isam1.internal.example.com"
  [isam.jwttoken.host2]="isam2.internal.example.com"
  [isam.jwttoken.port]="443"
  [isam.jwttoken.scheme]="https"
  [isam.jwttoken.path]="/json/jwt-token-exchange"
  [isam.jwttoken.connectTimeoutMs]="5000"
  [isam.jwttoken.ioTimeoutMs]="10000"
  [isam.jwttoken.appliesTo]="urn:isam:relying-party:jwt-token"
  [isam.jwttoken.tokenType]="urn:ietf:params:oauth:token-type:jwt"
  [isam.jwttoken.keyType]="http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer"
  [isam.jwttoken.requestType]="issue"
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
