#!/usr/bin/env bash
#
# Creates/updates the "ISAM.SamlUser.Config" KVM entries for the
# ISAM-SAML-User shared flow (type 2: WS-Trust with bearer token).
#
# Usage:
#   ORG=my-org ENV=my-env TOKEN=$(gcloud auth print-access-token) \
#     ./provision-kvm.sh

set -euo pipefail

: "${ORG:?Set ORG to your Apigee organization}"
: "${ENV:?Set ENV to your Apigee environment}"
: "${TOKEN:?Set TOKEN to a valid Apigee Management API bearer token}"

MAP_NAME="ISAM.SamlUser.Config"
BASE_URL="https://apigee.googleapis.com/v1/organizations/${ORG}/environments/${ENV}/keyvaluemaps"

declare -A KEYS=(
  [isam.saml.user.host1]="isam1.internal.example.com"
  [isam.saml.user.host2]="isam2.internal.example.com"
  [isam.saml.user.port]="443"
  [isam.saml.user.scheme]="https"
  [isam.saml.user.path]="/TrustServer/SecurityTokenServiceUser"
  [isam.saml.user.connectTimeoutMs]="5000"
  [isam.saml.user.ioTimeoutMs]="10000"
  [isam.saml.user.appliesTo]="urn:isam:relying-party:user"
  [isam.saml.user.tokenType]="urn:oasis:names:tc:SAML:2.0:assertion"
  [isam.saml.user.keyType]="http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer"
  [isam.saml.user.requestType]="http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
  [isam.saml.user.compressSaml]="false"
  [isam.saml.user.trustedSigningCertThumbprints]=""
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
