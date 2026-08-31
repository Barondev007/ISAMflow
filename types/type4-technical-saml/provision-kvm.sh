#!/usr/bin/env bash
#
# Creates/updates the "ISAM.SamlTechnical.Config" KVM entries for the
# ISAM-SAML-Technical shared flow (type 4: technical WS-Trust with bearer token).
#
# Usage:
#   ORG=my-org ENV=my-env TOKEN=$(gcloud auth print-access-token) \
#     ./provision-kvm.sh

set -euo pipefail

: "${ORG:?Set ORG to your Apigee organization}"
: "${ENV:?Set ENV to your Apigee environment}"
: "${TOKEN:?Set TOKEN to a valid Apigee Management API bearer token}"

MAP_NAME="ISAM.SamlTechnical.Config"
BASE_URL="https://apigee.googleapis.com/v1/organizations/${ORG}/environments/${ENV}/keyvaluemaps"

declare -A KEYS=(
  [isam.saml.technical.host1]="isam1.internal.example.com"
  [isam.saml.technical.host2]="isam2.internal.example.com"
  [isam.saml.technical.port]="443"
  [isam.saml.technical.scheme]="https"
  [isam.saml.technical.path]="/TrustServer/SecurityTokenServiceTechnical"
  [isam.saml.technical.connectTimeoutMs]="5000"
  [isam.saml.technical.ioTimeoutMs]="10000"
  [isam.saml.technical.appliesTo]="urn:isam:relying-party:technical"
  [isam.saml.technical.tokenType]="urn:oasis:names:tc:SAML:2.0:assertion"
  [isam.saml.technical.keyType]="http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer"
  [isam.saml.technical.requestType]="http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
  [isam.saml.technical.compressSaml]="false"
  [isam.saml.technical.trustedSigningCertThumbprints]=""
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
