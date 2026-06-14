#!/usr/bin/env bash
#
# ssi-cid-demo.sh — create a *self-signed* LWS identity and verify it end to end.
#
# Unlike the OpenID demo, Keycloak does NOT issue the credential here — the agent does. The script:
#   1. logs in as the Keycloak admin
#   2. ensures a realm, and enables unmanaged user attributes (so 'lws_jwk' can be stored)
#   3. ensures a user
#   4. generates an EC P-256 keypair (the agent keeps the private key)
#   5. registers the PUBLIC JWK on the user as the 'lws_jwk' attribute
#   6. dereferences the user's controlled identifier document (publishing that key)
#   7. mints a self-issued ES256 JWT (sub == iss == client_id == the document URL)
#   8. runs it through the provider's /lws-ssi-cid/verify endpoint
#
# Requirements: curl, jq, openssl, and a running Keycloak 26.7.0 with the lws-authn provider deployed.
# Defaults target `kc.sh start-dev` on http://localhost:8080 with admin/admin.
#
# Usage:
#   bash scripts/ssi-cid-demo.sh
#   KC_URL=https://kc.example ADMIN_PASS=secret USERNAME=bob bash scripts/ssi-cid-demo.sh

set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8080}"
REALM="${REALM:-lws-demo}"
USERNAME="${USERNAME:-alice}"
PASSWORD="${PASSWORD:-alice}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
KID="${KID:-agent-key-1}"
AUDIENCE="${AUDIENCE:-https://as.example}"

for tool in curl jq openssl xxd; do command -v "$tool" >/dev/null || { echo "$tool is required"; exit 1; }; done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

note() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }
api()  { curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" "$@"; }
b64u_str() { printf '%s' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '='; }
b64u_bin() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }     # stdin (binary) -> base64url

note "1. Admin login at $KC_URL"
ADMIN_TOKEN=$(curl -sS -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d username="$ADMIN_USER" -d password="$ADMIN_PASS" | jq -r '.access_token // empty')
[ -n "$ADMIN_TOKEN" ] || die "Admin login failed. Is Keycloak up at $KC_URL, and ADMIN_USER/ADMIN_PASS correct?"
echo "ok"

note "2. Ensure realm '$REALM' and enable unmanaged attributes"
if [ "$(api -o /dev/null -w '%{http_code}' "$KC_URL/admin/realms/$REALM")" = 404 ]; then
  api -X POST "$KC_URL/admin/realms" -H 'Content-Type: application/json' \
      -d "{\"realm\":\"$REALM\",\"enabled\":true,\"sslRequired\":\"external\"}"
  echo "created realm $REALM"
fi
# Keycloak 26 rejects undeclared attributes unless unmanaged attributes are allowed.
api "$KC_URL/admin/realms/$REALM/users/profile" \
  | jq '.unmanagedAttributePolicy = "ENABLED"' > "$WORK/profile.json"
api -X PUT "$KC_URL/admin/realms/$REALM/users/profile" -H 'Content-Type: application/json' -d @"$WORK/profile.json" >/dev/null
echo "unmanaged attributes enabled"

note "3. Ensure user '$USERNAME'"
USER_UUID=$(api "$KC_URL/admin/realms/$REALM/users?username=$USERNAME&exact=true" | jq -r '.[0].id // empty')
if [ -z "$USER_UUID" ]; then
  api -X POST "$KC_URL/admin/realms/$REALM/users" -H 'Content-Type: application/json' -d "$(cat <<JSON
{ "username":"$USERNAME","enabled":true,"emailVerified":true,"email":"$USERNAME@example.org",
  "credentials":[{"type":"password","value":"$PASSWORD","temporary":false}] }
JSON
)"
  USER_UUID=$(api "$KC_URL/admin/realms/$REALM/users?username=$USERNAME&exact=true" | jq -r '.[0].id')
  echo "created user $USERNAME ($USER_UUID)"
else
  echo "user $USERNAME already exists ($USER_UUID)"
fi

note "4. Generate the agent's EC P-256 keypair (private key stays with the agent)"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/priv.pem" 2>/dev/null
# Uncompressed public point (04 || X(32) || Y(32)) is the last 65 bytes of the DER SubjectPublicKeyInfo.
openssl ec -in "$WORK/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 65 > "$WORK/point.bin"
X=$(dd if="$WORK/point.bin" bs=1 skip=1  count=32 2>/dev/null | b64u_bin)
Y=$(dd if="$WORK/point.bin" bs=1 skip=33 count=32 2>/dev/null | b64u_bin)
JWK="{\"kid\":\"$KID\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"$X\",\"y\":\"$Y\"}"
echo "public JWK: $JWK"

note "5. Register the public JWK on the user (lws_jwk attribute)"
api "$KC_URL/admin/realms/$REALM/users/$USER_UUID" \
  | jq --arg jwk "$JWK" '.attributes = ((.attributes // {}) + {"lws_jwk":[$jwk]})' > "$WORK/user.json"
api -X PUT "$KC_URL/admin/realms/$REALM/users/$USER_UUID" -H 'Content-Type: application/json' -d @"$WORK/user.json" >/dev/null
echo "registered"

note "6. Dereference the controlled identifier document (publishes the key)"
CID=$(curl -sS -H 'Accept: application/ld+json' "$KC_URL/realms/$REALM/lws-ssi-cid/cid/$USER_UUID")
echo "$CID" | jq .
WEBID=$(echo "$CID" | jq -r .id)
[ -n "$WEBID" ] && [ "$WEBID" != null ] || die "Could not read the controlled identifier document 'id'."
if [ "$(echo "$CID" | jq '[.authentication[]?.publicKeyJwk] | length')" = 0 ]; then
  die "The document has no authentication key — the lws_jwk attribute was not stored (unmanaged attributes?)."
fi

note "7. Mint a self-issued ES256 JWT (sub == iss == client_id == $WEBID)"
NOW=$(date +%s)
HEADER="{\"alg\":\"ES256\",\"kid\":\"$KID\",\"typ\":\"JWT\"}"
PAYLOAD="{\"sub\":\"$WEBID\",\"iss\":\"$WEBID\",\"client_id\":\"$WEBID\",\"aud\":[\"$AUDIENCE\"],\"iat\":$NOW,\"exp\":$((NOW+300))}"
SIGNING_INPUT="$(b64u_str "$HEADER").$(b64u_str "$PAYLOAD")"

# Sign -> DER ECDSA signature, then convert to JOSE raw R||S (two 32-byte big-endian integers).
printf '%s' "$SIGNING_INPUT" | openssl dgst -sha256 -sign "$WORK/priv.pem" -out "$WORK/sig.der"
INTS=$(openssl asn1parse -inform DER -in "$WORK/sig.der" | awk -F: '/INTEGER/{gsub(/ /,"",$NF);print $NF}')
# Each integer to exactly 32 bytes (64 hex): left-pad short values, trim any leading 00 to the last 64.
R=$(printf '%064s' "$(printf '%s\n' "$INTS" | sed -n 1p)" | tr ' ' '0'); R="${R: -64}"
S=$(printf '%064s' "$(printf '%s\n' "$INTS" | sed -n 2p)" | tr ' ' '0'); S="${S: -64}"
SIG=$(printf '%s' "$R$S" | xxd -r -p | b64u_bin)   # 64-byte raw R||S (JOSE), base64url
JWT="$SIGNING_INPUT.$SIG"
echo "$JWT"

note "8. Verify the self-signed credential with the provider's /lws-ssi-cid/verify endpoint"
RESULT=$(curl -sS -X POST "$KC_URL/realms/$REALM/lws-ssi-cid/verify" --data-urlencode "credential=$JWT")
echo "$RESULT" | jq .

if [ "$(printf '%s' "$RESULT" | jq -r '.valid // false')" = true ]; then
  note "PASS"
  echo "'$WEBID' is a working self-signed LWS identity."
  echo "Present this JWT to an LWS server, e.g.:"
  echo "    curl https://pod.example/ -H \"Authorization: Bearer \$JWT\""
  echo "The server fetches the document above, selects the key by 'kid', and validates the signature."
else
  die "FAIL — the credential did not validate (see errors above)."
fi
