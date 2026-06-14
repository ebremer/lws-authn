#!/usr/bin/env bash
#
# lws-demo.sh — provision an LWS identity in Keycloak and verify it end to end.
#
# It will, idempotently:
#   1. log in as the Keycloak admin
#   2. ensure a realm exists
#   3. ensure a client exists with the "LWS WebID Subject" protocol mapper
#   4. ensure a user exists (with a password)
#   5. obtain an ID Token for that user
#   6. dereference the resulting WebID (the controlled identifier document)
#   7. run the credential through the provider's /verify endpoint
#
# Requirements: curl, jq, and a running Keycloak 26.7.0 with the lws-authn provider deployed
# (kc.sh build && kc.sh start). Defaults target `kc.sh start-dev` on http://localhost:8080
# with the bootstrap admin admin/admin.
#
# Usage:
#   bash scripts/lws-demo.sh
#   KC_URL=https://kc.example ADMIN_PASS=secret USERNAME=bob PASSWORD=s3cret bash scripts/lws-demo.sh
#
# To use an externally-hosted WebID instead of a Keycloak-hosted one, set WEBID_ATTRIBUTE to the
# user-attribute name that holds it (and set that attribute on the user yourself) — see the
# walkthrough's "Bring your own WebID" section.

set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8080}"
REALM="${REALM:-lws-demo}"
CLIENT_ID="${CLIENT_ID:-lws-app}"
USERNAME="${USERNAME:-alice}"
PASSWORD="${PASSWORD:-alice}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
WEBID_ATTRIBUTE="${WEBID_ATTRIBUTE:-}"   # empty => Keycloak hosts the WebID at {iss}/lws/cid/{userId}

command -v curl >/dev/null || { echo "curl is required"; exit 1; }
command -v jq   >/dev/null || { echo "jq is required";   exit 1; }

note() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }
api()  { curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" "$@"; }

# decode a JWT payload (base64url) to JSON; works with both GNU and BSD base64
jwt_payload() {
  local p; p=$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+')
  case $(( ${#p} % 4 )) in 2) p="${p}==";; 3) p="${p}=";; esac
  printf '%s' "$p" | base64 -d 2>/dev/null || printf '%s' "$p" | base64 -D 2>/dev/null
}

note "1. Admin login at $KC_URL"
ADMIN_TOKEN=$(curl -sS -X POST "$KC_URL/realms/master/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=admin-cli \
  -d username="$ADMIN_USER" -d password="$ADMIN_PASS" | jq -r '.access_token // empty')
[ -n "$ADMIN_TOKEN" ] || die "Admin login failed. Is Keycloak up at $KC_URL, and are ADMIN_USER/ADMIN_PASS correct?"
echo "ok"

note "2. Ensure realm '$REALM'"
if [ "$(api -o /dev/null -w '%{http_code}' "$KC_URL/admin/realms/$REALM")" = 404 ]; then
  api -X POST "$KC_URL/admin/realms" -H 'Content-Type: application/json' \
      -d "{\"realm\":\"$REALM\",\"enabled\":true,\"sslRequired\":\"external\"}"
  echo "created realm $REALM"
else
  echo "realm $REALM already exists"
fi

MAPPER=$(cat <<JSON
{
  "name": "lws-webid-sub",
  "protocol": "openid-connect",
  "protocolMapper": "lws-webid-sub-mapper",
  "consentRequired": false,
  "config": {
    "lws.webid.attribute": "$WEBID_ATTRIBUTE",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "userinfo.token.claim": "true"
  }
}
JSON
)

note "3. Ensure client '$CLIENT_ID' with the LWS WebID Subject mapper"
CLIENT_UUID=$(api "$KC_URL/admin/realms/$REALM/clients?clientId=$CLIENT_ID" | jq -r '.[0].id // empty')
if [ -z "$CLIENT_UUID" ]; then
  api -X POST "$KC_URL/admin/realms/$REALM/clients" -H 'Content-Type: application/json' -d "$(cat <<JSON
{
  "clientId": "$CLIENT_ID",
  "enabled": true,
  "protocol": "openid-connect",
  "publicClient": true,
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "redirectUris": ["*"],
  "protocolMappers": [ $MAPPER ]
}
JSON
)"
  echo "created client $CLIENT_ID (with LWS mapper)"
else
  HAS=$(api "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/protocol-mappers/models" \
        | jq '[.[] | select(.protocolMapper=="lws-webid-sub-mapper")] | length')
  if [ "$HAS" = 0 ]; then
    api -X POST "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/protocol-mappers/models" \
        -H 'Content-Type: application/json' -d "$MAPPER"
    echo "added LWS mapper to existing client $CLIENT_ID"
  else
    echo "client $CLIENT_ID already has the LWS mapper"
  fi
fi

note "4. Ensure user '$USERNAME'"
USER_UUID=$(api "$KC_URL/admin/realms/$REALM/users?username=$USERNAME&exact=true" | jq -r '.[0].id // empty')
if [ -z "$USER_UUID" ]; then
  api -X POST "$KC_URL/admin/realms/$REALM/users" -H 'Content-Type: application/json' -d "$(cat <<JSON
{
  "username": "$USERNAME",
  "enabled": true,
  "emailVerified": true,
  "email": "$USERNAME@example.org",
  "credentials": [ { "type": "password", "value": "$PASSWORD", "temporary": false } ]
}
JSON
)"
  USER_UUID=$(api "$KC_URL/admin/realms/$REALM/users?username=$USERNAME&exact=true" | jq -r '.[0].id')
  echo "created user $USERNAME ($USER_UUID)"
else
  echo "user $USERNAME already exists ($USER_UUID)"
fi

note "5. Obtain an ID Token for '$USERNAME'"
TOKEN_RESPONSE=$(curl -sS -X POST "$KC_URL/realms/$REALM/protocol/openid-connect/token" \
  -d grant_type=password -d client_id="$CLIENT_ID" -d scope=openid \
  -d username="$USERNAME" -d password="$PASSWORD")
ID_TOKEN=$(printf '%s' "$TOKEN_RESPONSE" | jq -r '.id_token // empty')
[ -n "$ID_TOKEN" ] || { echo "$TOKEN_RESPONSE" | jq .; die "Could not obtain an id_token."; }

PAYLOAD=$(jwt_payload "$ID_TOKEN")
SUB=$(printf '%s' "$PAYLOAD" | jq -r .sub)
ISS=$(printf '%s' "$PAYLOAD" | jq -r .iss)
echo "sub (WebID) = $SUB"
echo "iss         = $ISS"

note "6. Dereference the WebID — the controlled identifier document a verifier fetches"
curl -sS -H 'Accept: text/turtle' "$SUB" || echo "(could not fetch $SUB — is it reachable from here?)"
echo

note "7. Verify the credential with the provider's /verify endpoint"
RESULT=$(curl -sS -X POST "$ISS/lws/verify" --data-urlencode "credential=$ID_TOKEN")
echo "$RESULT" | jq .

if [ "$(printf '%s' "$RESULT" | jq -r '.valid // false')" = true ]; then
  note "PASS"
  echo "'$SUB' is a working LWS identity issued by $ISS."
  echo "Present this ID Token to an LWS server, e.g.:"
  echo "    curl https://pod.example/ -H \"Authorization: Bearer \$ID_TOKEN\""
  echo "The server fetches the WebID above, sees it names this issuer as its OpenID Provider,"
  echo "validates the signature, and authenticates the request as that WebID."
else
  die "FAIL — the credential did not validate (see errors above)."
fi
