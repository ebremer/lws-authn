#!/usr/bin/env bash
# Copyright Erich Bremer.
#
# SPDX-License-Identifier: Apache-2.0
#
# lws-demo.sh — provision an LWS identity in Keycloak and verify it end to end.
#
# It will, idempotently:
#   1. log in as the Keycloak admin
#   2. ensure a realm exists
#   3. ensure a client exists with the "LWS WebID Subject" protocol mapper
#   4. ensure a user exists (with a password), holding the role that may call /verify
#   5. obtain an ID Token for that user
#   6. dereference the resulting WebID (the controlled identifier document)
#   7. run the credential through the provider's /verify endpoint
#
# Requirements: curl 7.76 or later, jq, and a running Keycloak 26.8 (26.8.0 or later) with the
# lws-authn provider deployed (kc.sh build && kc.sh start). Defaults target `kc.sh start-dev` on
# http://localhost:8080 with the bootstrap admin admin/admin.
#
# Usage:
#   bash scripts/lws-demo.sh
#   KC_URL=https://kc.example ADMIN_PASS=secret DEMO_USER=bob PASSWORD=s3cret bash scripts/lws-demo.sh
#
# PASSWORD is required unless KC_URL is this machine. The client it creates allows only the password
# grant, which is what makes it scriptable; it is a demo client, not one to build an app on. On a real
# server, delete the realm when you are done (docs/INSTALL.md §13).
#
# The user is DEMO_USER, not USERNAME: Windows sets USERNAME to the login name, so under Git Bash the
# script used to create a user named after whoever ran it.
#
# To use an externally-hosted WebID instead of a Keycloak-hosted one, set WEBID_ATTRIBUTE to the
# user-attribute name that holds it (and set that attribute on the user yourself) — see the
# walkthrough's "Bring your own WebID" section.

set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8080}"
REALM="${REALM:-lws-demo}"
CLIENT_ID="${CLIENT_ID:-lws-app}"
DEMO_USER="${DEMO_USER:-alice}"
PASSWORD="${PASSWORD:-}"   # required unless KC_URL is this machine; see below
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
WEBID_ATTRIBUTE="${WEBID_ATTRIBUTE:-}"   # empty => Keycloak hosts the WebID at {iss}/lws/cid/{userId}
VERIFY_ROLE="${VERIFY_ROLE:-lws-verifier}"   # the verify endpoints' `role` setting

command -v curl >/dev/null || { echo "curl is required"; exit 1; }
command -v jq   >/dev/null || { echo "jq is required";   exit 1; }

umask 077
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

note() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; exit 1; }
# A field of the JSON on stdin, or nothing when it is not JSON: a proxy's HTML error page must reach the
# script's own message, not stop it inside jq.
json() { jq -r "$1" 2>/dev/null || true; }

# Passwords and tokens never go on a command line, where `ps` shows them to everyone on the machine:
# passwords reach curl on stdin, tokens through a header file only this user can read.
bearer_header() { printf 'Authorization: Bearer %s\n' "$2" > "$1"; }

# POSTs to the token endpoint of realm $1 for client $2, user $3, with the password on stdin.
password_grant() {
  curl -sS -X POST "$KC_URL/realms/$1/protocol/openid-connect/token" \
    -d grant_type=password --data-urlencode "client_id=$2" --data-urlencode "username=$3" \
    --data-urlencode "password@-" "${@:4}"
}

# The admin API. A request it refuses stops the script with Keycloak's answer, rather than printing
# "created …" over a failure.
api()        { curl -sS --fail-with-body -H @"$WORK/admin.h" "$@" || { echo >&2; die "The admin API refused that request (above)."; }; }
api_status() { curl -sS -o /dev/null -w '%{http_code}' -H @"$WORK/admin.h" "$@"; }

# The /verify endpoints are authenticated by default (see "Securing the verify endpoints" in
# docs/configuration.md). VERIFY_TOKEN is the *caller's* credential; the credential being verified always
# travels in the form body. Leave VERIFY_TOKEN empty only if the deployment runs them in
# `public` mode.
verify_post() {
  local url="$1"; shift
  if [ -n "${VERIFY_TOKEN:-}" ]; then
    bearer_header "$WORK/verify.h" "$VERIFY_TOKEN"
    curl -sS -X POST -H @"$WORK/verify.h" "$@" "$url"
  else
    curl -sS -X POST "$@" "$url"
  fi
}

# The user's password defaults to "alice" only on a server on this machine. Anywhere else that is a
# known password on a real server: anyone could log in as the user and — since it holds the verifier
# role — call /verify. So elsewhere it must be given.
if [ -z "$PASSWORD" ]; then
  case "$KC_URL" in
    http://localhost|http://localhost:*|http://127.0.0.1|http://127.0.0.1:*) PASSWORD=alice ;;
    *) die "Set PASSWORD for '$DEMO_USER' — on $KC_URL a default password would be public. For example:
    PASSWORD=\$(openssl rand -base64 18) KC_URL=$KC_URL bash $0" ;;
  esac
fi

# A bearer caller of a verify endpoint must hold the verifier realm role (docs/configuration.md,
# "Securing the verify endpoints"). Create it if this realm lacks it, and grant it to user $1.
ensure_verifier_role() {
  if [ "$(api_status "$KC_URL/admin/realms/$REALM/roles/$VERIFY_ROLE")" = 404 ]; then
    jq -n --arg name "$VERIFY_ROLE" '{name: $name, description: "May call the lws-authn verify endpoints"}' \
      | api -X POST "$KC_URL/admin/realms/$REALM/roles" -H 'Content-Type: application/json' --data-binary @-
    echo "created realm role $VERIFY_ROLE"
  fi
  api "$KC_URL/admin/realms/$REALM/roles/$VERIFY_ROLE" | jq -c '[.]' \
    | api -X POST "$KC_URL/admin/realms/$REALM/users/$1/role-mappings/realm" \
          -H 'Content-Type: application/json' --data-binary @-
  echo "granted $VERIFY_ROLE"
}

# The id of user $DEMO_USER in $REALM, or nothing.
user_id() {
  api --get --data-urlencode "username=$DEMO_USER" -d exact=true "$KC_URL/admin/realms/$REALM/users" \
    | json '.[0].id // empty'
}

# decode a JWT payload (base64url) to JSON; works with both GNU and BSD base64
jwt_payload() {
  local p; p=$(printf '%s' "$1" | cut -d. -f2 | tr '_-' '/+')
  case $(( ${#p} % 4 )) in 2) p="${p}==";; 3) p="${p}=";; esac
  printf '%s' "$p" | base64 -d 2>/dev/null || printf '%s' "$p" | base64 -D 2>/dev/null
}

note "1. Admin login at $KC_URL"
ADMIN_TOKEN=$(printf '%s' "$ADMIN_PASS" | password_grant master admin-cli "$ADMIN_USER" | json '.access_token // empty')
[ -n "$ADMIN_TOKEN" ] || die "Admin login failed. Is Keycloak up at $KC_URL, and are ADMIN_USER/ADMIN_PASS correct?"
bearer_header "$WORK/admin.h" "$ADMIN_TOKEN"
echo "ok"

note "2. Ensure realm '$REALM'"
if [ "$(api_status "$KC_URL/admin/realms/$REALM")" = 404 ]; then
  jq -n --arg realm "$REALM" '{realm: $realm, enabled: true, sslRequired: "external"}' \
    | api -X POST "$KC_URL/admin/realms" -H 'Content-Type: application/json' --data-binary @-
  echo "created realm $REALM"
else
  echo "realm $REALM already exists"
fi

MAPPER=$(jq -n --arg attribute "$WEBID_ATTRIBUTE" '{
  name: "lws-webid-sub",
  protocol: "openid-connect",
  protocolMapper: "lws-webid-sub-mapper",
  consentRequired: false,
  config: {"lws.webid.attribute": $attribute, "id.token.claim": "true", "access.token.claim": "false"}
}')

note "3. Ensure client '$CLIENT_ID' with the LWS WebID Subject mapper"
CLIENT_UUID=$(api --get --data-urlencode "clientId=$CLIENT_ID" "$KC_URL/admin/realms/$REALM/clients" \
              | json '.[0].id // empty')
if [ -z "$CLIENT_UUID" ]; then
  jq -n --arg clientId "$CLIENT_ID" --argjson mapper "$MAPPER" '{
    clientId: $clientId,
    enabled: true,
    protocol: "openid-connect",
    publicClient: true,
    standardFlowEnabled: false,
    directAccessGrantsEnabled: true,
    fullScopeAllowed: false,
    protocolMappers: [$mapper]
  }' | api -X POST "$KC_URL/admin/realms/$REALM/clients" -H 'Content-Type: application/json' --data-binary @-
  echo "created client $CLIENT_ID (with LWS mapper)"
else
  HAS=$(api "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/protocol-mappers/models" \
        | json '[.[] | select(.protocolMapper=="lws-webid-sub-mapper")] | length')
  if [ "$HAS" = 0 ]; then
    printf '%s' "$MAPPER" | api -X POST "$KC_URL/admin/realms/$REALM/clients/$CLIENT_UUID/protocol-mappers/models" \
        -H 'Content-Type: application/json' --data-binary @-
    echo "added LWS mapper to existing client $CLIENT_ID"
  else
    echo "client $CLIENT_ID already has the LWS mapper"
  fi
fi

note "4. Ensure user '$DEMO_USER'"
USER_UUID=$(user_id)
if [ -z "$USER_UUID" ]; then
  # The password is jq's input, not its argument, so it never appears in a process list.
  printf '%s' "$PASSWORD" | jq -Rs --arg username "$DEMO_USER" '{
    username: $username,
    enabled: true,
    emailVerified: true,
    email: ($username + "@example.org"),
    credentials: [{type: "password", value: ., temporary: false}]
  }' | api -X POST "$KC_URL/admin/realms/$REALM/users" -H 'Content-Type: application/json' --data-binary @-
  USER_UUID=$(user_id)
  [ -n "$USER_UUID" ] || die "Created user $DEMO_USER, but cannot find it."
  echo "created user $DEMO_USER ($USER_UUID)"
else
  echo "user $DEMO_USER already exists ($USER_UUID)"
fi
# The same user calls /verify below, with the access token from the same login.
ensure_verifier_role "$USER_UUID"

note "5. Obtain an ID Token for '$DEMO_USER'"
TOKEN_RESPONSE=$(printf '%s' "$PASSWORD" | password_grant "$REALM" "$CLIENT_ID" "$DEMO_USER" -d scope=openid)
ID_TOKEN=$(printf '%s' "$TOKEN_RESPONSE" | json '.id_token // empty')
[ -n "$ID_TOKEN" ] || { printf '%s\n' "$TOKEN_RESPONSE"; die "Could not obtain an id_token."; }
# The access token from the same response authenticates *us* to the verify endpoint; the ID Token is
# the credential being verified. Two different things, two different places in the request.
VERIFY_TOKEN="${VERIFY_TOKEN:-$(printf '%s' "$TOKEN_RESPONSE" | json '.access_token // empty')}"

PAYLOAD=$(jwt_payload "$ID_TOKEN")
SUB=$(printf '%s' "$PAYLOAD" | json .sub)
ISS=$(printf '%s' "$PAYLOAD" | json .iss)
echo "sub (WebID) = $SUB"
echo "iss         = $ISS"

note "6. Dereference the WebID — the controlled identifier document a verifier fetches"
curl -sS -H 'Accept: text/turtle' "$SUB" || echo "(could not fetch $SUB — is it reachable from here?)"
echo

note "7. Verify the credential with the provider's /verify endpoint"
RESULT=$(printf '%s' "$ID_TOKEN" | verify_post "$ISS/lws/verify" --data-urlencode "credential@-")
printf '%s' "$RESULT" | jq . 2>/dev/null || printf '%s\n' "$RESULT"

if [ "$(printf '%s' "$RESULT" | json '.valid // false')" = true ]; then
  note "PASS"
  echo "'$SUB' is a working LWS identity issued by $ISS."
  echo "Present this ID Token to an LWS server, e.g.:"
  echo "    curl https://pod.example/ -H \"Authorization: Bearer \$ID_TOKEN\""
  echo "The server fetches the WebID above, sees it names this issuer as its OpenID Provider,"
  echo "validates the signature, and authenticates the request as that WebID."
else
  die "FAIL — the credential did not validate (see errors above)."
fi
