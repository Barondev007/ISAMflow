#!/usr/bin/env bash
#
# Creates/updates the "ISAM.JwtSaml.Config" KVM entries for the
# ISAM-JWT-SAML shared flow (type 5: JWT-style JSON request, SAML assertion
# in the JSON response).
#
# Usage:
#   ORG=my-org ENV=my-env TOKEN=$(gcloud auth print-access-token) \
#     ./provision-kvm.sh

set -euo pipefail

: "${ORG:?Set ORG to your Apigee organization}"
: "${ENV:?Set ENV to your Apigee environment}"
: "${TOKEN:?Set TOKEN to a valid Apigee Management API bearer token}"

MAP_NAME="ISAM.JwtSaml.Config"
BASE_URL="https://apigee.googleapis.com/v1/organizations/${ORG}/environments/${ENV}/keyvaluemaps"

declare -A KEYS=(
  [isam.jwtsaml.host1]="isam1.internal.example.com"
  [isam.jwtsaml.host2]="isam2.internal.example.com"
  [isam.jwtsaml.port]="443"
  [isam.jwtsaml.scheme]="https"
  [isam.jwtsaml.path]="/json/saml-token-exchange"
  [isam.jwtsaml.connectTimeoutMs]="5000"
  [isam.jwtsaml.ioTimeoutMs]="10000"
  [isam.jwtsaml.appliesTo]="urn:isam:relying-party:jwt-saml"
  [isam.jwtsaml.tokenType]="urn:oasis:names:tc:SAML:2.0:assertion"
  [isam.jwtsaml.keyType]="http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer"
  [isam.jwtsaml.requestType]="issue"
  [isam.jwtsaml.compressSaml]="false"
  [isam.jwtsaml.trustedSigningCertThumbprints]=""
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
