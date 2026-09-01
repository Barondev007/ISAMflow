#!/usr/bin/env bash
#
# Points all six types' KVM configs at the Mock-ISAM proxy (see
# dev-testing/Mock-ISAM/), instead of the real placeholder ISAM hosts each
# type's own types/type*/provision-kvm.sh ships with. Run this AFTER
# deploying Mock-ISAM and BEFORE testing via ISAM-Test-Caller.
#
# Usage:
#   ORG=my-org ENV=my-dev-env TOKEN=$(gcloud auth print-access-token) \
#   MOCK_HOST=my-org-my-dev-env.apigee.net \
#     ./provision-kvm-dev.sh
#
# MOCK_HOST is wherever Mock-ISAM is actually reachable once deployed --
# typically the same org/env hostname this script is provisioning KVMs
# into, since Mock-ISAM and the six type-specific shared flows normally
# live in the same environment for dev testing.

set -euo pipefail

: "${ORG:?Set ORG to your Apigee organization}"
: "${ENV:?Set ENV to your Apigee environment}"
: "${TOKEN:?Set TOKEN to a valid Apigee Management API bearer token}"
: "${MOCK_HOST:?Set MOCK_HOST to the hostname Mock-ISAM is reachable at (e.g. org-env.apigee.net)}"

BASE_URL="https://apigee.googleapis.com/v1/organizations/${ORG}/environments/${ENV}/keyvaluemaps"

# Optional: set to the SHA-256 thumbprint printed by Mock-ISAM's /
# (help route) or dev-testing/Mock-ISAM/README.md, to test signing-cert
# pinning end to end. Leave empty to test signature validation without
# pinning (the default for the "real" provisioning scripts too).
TRUSTED_THUMBPRINT="${TRUSTED_THUMBPRINT:-}"

write_entry() {
    local map_name="$1" key="$2" value="$3"
    local body
    body=$(python3 -c 'import json,sys; print(json.dumps({"name": sys.argv[1], "value": sys.argv[2]}))' "${key}" "${value}")
    local status
    status=$(curl -sS -o /tmp/kvm-create-resp.json -w '%{http_code}' -X POST \
        "${BASE_URL}/${map_name}/entries" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        -d "${body}")
    if [[ "${status}" == "409" ]]; then
        curl -sS -o /dev/null -w '    updated (%{http_code})\n' -X PUT \
            "${BASE_URL}/${map_name}/entries/${key}" \
            -H "Authorization: Bearer ${TOKEN}" \
            -H "Content-Type: application/json" \
            -d "${body}"
    else
        echo "    created (${status})"
    fi
}

ensure_map() {
    local map_name="$1"
    curl -sS -o /dev/null -w '  KVM %{http_code}\n' -X POST "${BASE_URL}" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"${map_name}\"}" || true
}

# map_name, key_prefix, mock_path_segment, tokenType, requestType
TYPES=(
  "ISAM.SamlLight.Config|isam.saml.light|light|urn:oasis:names:tc:SAML:2.0:assertion|http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
  "ISAM.SamlUser.Config|isam.saml.user|user|urn:oasis:names:tc:SAML:2.0:assertion|http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
  "ISAM.SamlTP.Config|isam.saml.tp|tp|urn:oasis:names:tc:SAML:2.0:assertion|http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
  "ISAM.SamlTechnical.Config|isam.saml.technical|technical|urn:oasis:names:tc:SAML:2.0:assertion|http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
  "ISAM.JwtSaml.Config|isam.jwtsaml|jwt-saml|urn:oasis:names:tc:SAML:2.0:assertion|issue"
  "ISAM.JwtToken.Config|isam.jwttoken|jwt-token|urn:ietf:params:oauth:token-type:jwt|issue"
)

for entry in "${TYPES[@]}"; do
    IFS='|' read -r map_name key_prefix mock_path token_type request_type <<< "${entry}"
    echo "=== ${map_name} -> https://${MOCK_HOST}/mock-isam/${mock_path} ==="
    ensure_map "${map_name}"

    write_entry "${map_name}" "${key_prefix}.host1" "${MOCK_HOST}"
    write_entry "${map_name}" "${key_prefix}.host2" "${MOCK_HOST}"
    write_entry "${map_name}" "${key_prefix}.port" "443"
    write_entry "${map_name}" "${key_prefix}.scheme" "https"
    write_entry "${map_name}" "${key_prefix}.path" "/mock-isam/${mock_path}"
    write_entry "${map_name}" "${key_prefix}.connectTimeoutMs" "5000"
    write_entry "${map_name}" "${key_prefix}.ioTimeoutMs" "10000"
    write_entry "${map_name}" "${key_prefix}.appliesTo" "urn:isam:relying-party:dev-test"
    write_entry "${map_name}" "${key_prefix}.tokenType" "${token_type}"
    write_entry "${map_name}" "${key_prefix}.keyType" "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer"
    write_entry "${map_name}" "${key_prefix}.requestType" "${request_type}"

    # type 6 (ISAM.JwtToken.Config) has no compressSaml/trustedSigningCertThumbprints
    # keys at all -- there's no SAML assertion involved for that type.
    if [[ "${map_name}" != "ISAM.JwtToken.Config" ]]; then
        write_entry "${map_name}" "${key_prefix}.compressSaml" "false"
        write_entry "${map_name}" "${key_prefix}.trustedSigningCertThumbprints" "${TRUSTED_THUMBPRINT}"
    fi
done

echo "Done. All six types now point at https://${MOCK_HOST}/mock-isam/*"
echo "To test failover, temporarily set one type's *.host1 (or path) to route"
echo "through /mock-isam/<type>/fail instead -- see dev-testing/Mock-ISAM/README.md."
