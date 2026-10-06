#!/usr/bin/env bash
# Copyright Erich Bremer.
#
# SPDX-License-Identifier: Apache-2.0
#
# ssi-cid-demo.sh — create a *self-signed* LWS identity and verify it end to end.
#
# Unlike the OpenID demo, Keycloak does NOT issue the credential here — the agent does. The script:
#   1. logs in as the Keycloak admin
#   2. ensures a realm, and allows admin-managed unmanaged user attributes (so 'lws_jwk' can be
#      stored by an admin but NOT by the end user -- a user who can set their own key can mint
#      credentials for their own identity)
#   3. ensures a user
#   4. generates an EC P-256 keypair (the agent keeps the private key)
#   5. registers the PUBLIC JWK on the user as the 'lws_jwk' attribute
#   6. dereferences the user's controlled identifier document (publishing that key)
#   7. mints a self-issued ES256 JWT (sub == iss == client_id == the document URL)
#   8. runs it through the provider's /lws-ssi-cid/verify endpoint
#
# Requirements: curl 7.76 or later, jq, openssl, xxd, and a running Keycloak 26.8 (26.8.0 or later)
# with the lws-authn provider deployed. Defaults target `kc.sh start-dev` on http://localhost:8080 with
# admin/admin.
#
# Usage:
#   bash scripts/ssi-cid-demo.sh
#   KC_URL=https://kc.example ADMIN_PASS=secret DEMO_USER=bob PASSWORD=s3cret bash scripts/ssi-cid-demo.sh
#
# PASSWORD is required unless KC_URL is this machine. On a real server, delete the user — or the realm —
# when you are done (docs/INSTALL.md §13). The user is DEMO_USER, not USERNAME, which Windows sets to
# the login name.

set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8080}"
REALM="${REALM:-lws-demo}"
DEMO_USER="${DEMO_USER:-alice}"
PASSWORD="${PASSWORD:-}"   # required unless KC_URL is this machine; see below
VERIFY_ROLE="${VERIFY_ROLE:-lws-verifier}"   # the verify endpoints' `role` setting
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin}"
KID="${KID:-agent-key-1}"
AUDIENCE="${AUDIENCE:-https://as.example}"

for tool in curl jq openssl xxd; do command -v "$tool" >/dev/null || { echo "$tool is required"; exit 1; }; done

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
# "registered" over a failure.
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

b64u_str() { printf '%s' "$1" | openssl base64 -A | tr '+/' '-_' | tr -d '='; }
b64u_bin() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }     # stdin (binary) -> base64url

note "1. Admin login at $KC_URL"
ADMIN_TOKEN=$(printf '%s' "$ADMIN_PASS" | password_grant master admin-cli "$ADMIN_USER" | json '.access_token // empty')
[ -n "$ADMIN_TOKEN" ] || die "Admin login failed. Is Keycloak up at $KC_URL, and ADMIN_USER/ADMIN_PASS correct?"
bearer_header "$WORK/admin.h" "$ADMIN_TOKEN"
echo "ok"

note "2. Ensure realm '$REALM' and allow admin-managed unmanaged attributes"
if [ "$(api_status "$KC_URL/admin/realms/$REALM")" = 404 ]; then
  jq -n --arg realm "$REALM" '{realm: $realm, enabled: true, sslRequired: "external"}' \
    | api -X POST "$KC_URL/admin/realms" -H 'Content-Type: application/json' --data-binary @-
  echo "created realm $REALM"
fi
# Keycloak 26 rejects undeclared attributes unless unmanaged attributes are allowed.
# ADMIN_EDIT, not ENABLED: ENABLED lets the *end user* manage unmanaged attributes, and 'lws_jwk'
# is the key their own controlled identifier document publishes. A user who can write it can register
# any key against their identity and sign credentials for it.
api "$KC_URL/admin/realms/$REALM/users/profile" | jq '.unmanagedAttributePolicy = "ADMIN_EDIT"' \
  | api -X PUT "$KC_URL/admin/realms/$REALM/users/profile" -H 'Content-Type: application/json' --data-binary @-
echo "unmanaged attributes set to ADMIN_EDIT (admins may write lws_jwk; users may not)"

note "3. Ensure user '$DEMO_USER'"
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
ensure_verifier_role "$USER_UUID"

note "4. Obtain a caller token for the verify endpoint"
# admin-cli exists in every realm and allows the password grant, so this needs no extra client.
VERIFY_TOKEN="${VERIFY_TOKEN:-$(printf '%s' "$PASSWORD" | password_grant "$REALM" admin-cli "$DEMO_USER" \
                                | json '.access_token // empty')}"
[ -n "$VERIFY_TOKEN" ] || echo "warning: no caller token; /verify will refuse unless it runs in 'public' mode"

note "5. Generate the agent's EC P-256 keypair (private key stays with the agent)"
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/priv.pem" 2>/dev/null
# Uncompressed public point (04 || X(32) || Y(32)) is the last 65 bytes of the DER SubjectPublicKeyInfo.
openssl ec -in "$WORK/priv.pem" -pubout -outform DER 2>/dev/null | tail -c 65 > "$WORK/point.bin"
X=$(dd if="$WORK/point.bin" bs=1 skip=1  count=32 2>/dev/null | b64u_bin)
Y=$(dd if="$WORK/point.bin" bs=1 skip=33 count=32 2>/dev/null | b64u_bin)
JWK=$(jq -cn --arg kid "$KID" --arg x "$X" --arg y "$Y" '{kid: $kid, kty: "EC", crv: "P-256", x: $x, y: $y}')
echo "public JWK: $JWK"

note "6. Register the public JWK on the user (lws_jwk attribute)"
api "$KC_URL/admin/realms/$REALM/users/$USER_UUID" \
  | jq --arg jwk "$JWK" '.attributes = ((.attributes // {}) + {"lws_jwk": [$jwk]})' \
  | api -X PUT "$KC_URL/admin/realms/$REALM/users/$USER_UUID" -H 'Content-Type: application/json' --data-binary @-
echo "registered"

note "7. Dereference the controlled identifier document (publishes the key)"
CID=$(curl -sS -H 'Accept: application/ld+json' "$KC_URL/realms/$REALM/lws-ssi-cid/cid/$USER_UUID") \
  || die "Could not fetch the controlled identifier document."
printf '%s' "$CID" | jq . 2>/dev/null || printf '%s\n' "$CID"
WEBID=$(printf '%s' "$CID" | json '.id // empty')
[ -n "$WEBID" ] || die "Could not read the controlled identifier document's 'id' (the answer is above)."
if [ "$(printf '%s' "$CID" | json '[.authentication[]?.publicKeyJwk] | length')" = 0 ]; then
  die "The document has no authentication key — the lws_jwk attribute was not stored (unmanaged attributes?)."
fi

note "8. Mint a self-issued ES256 JWT (sub == iss == client_id == $WEBID)"
NOW=$(date +%s)
HEADER=$(jq -cn --arg kid "$KID" '{alg: "ES256", kid: $kid, typ: "JWT"}')
PAYLOAD=$(jq -cn --arg id "$WEBID" --arg aud "$AUDIENCE" --argjson now "$NOW" \
          '{sub: $id, iss: $id, client_id: $id, aud: [$aud], iat: $now, exp: ($now + 300)}')
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

note "9. Verify the self-signed credential with the provider's /lws-ssi-cid/verify endpoint"
RESULT=$(printf '%s' "$JWT" | verify_post "$KC_URL/realms/$REALM/lws-ssi-cid/verify" \
  --data-urlencode "credential@-" --data-urlencode "audience=$AUDIENCE")
printf '%s' "$RESULT" | jq . 2>/dev/null || printf '%s\n' "$RESULT"

if [ "$(printf '%s' "$RESULT" | json '.valid // false')" = true ]; then
  note "PASS"
  echo "'$WEBID' is a working self-signed LWS identity."
  echo "Present this JWT to an LWS server, e.g.:"
  echo "    curl https://pod.example/ -H \"Authorization: Bearer \$JWT\""
  echo "The server fetches the document above, selects the key by 'kid', and validates the signature."
else
  die "FAIL — the credential did not validate (see errors above)."
fi
