#!/usr/bin/env bash
#
# ssi-did-key-demo.sh — mint a self-signed did:key credential and verify it end to end.
#
# The did:key suite needs no realm/user/hosting — the public key lives in the identifier — so this
# only mints a key + JWT and calls the verify endpoint. It uses Node for the crypto (P-256/Ed25519
# key generation, point compression, base58btc, ES256/EdDSA signing) since base58 is impractical in
# pure shell.
#
# Requirements: curl, jq, node, and a running Keycloak 26.7.0 with the lws-authn provider deployed.
# Defaults target `kc.sh start-dev` on http://localhost:8080, realm `master` (any realm works —
# the verifier is realm-agnostic).
#
# Usage:
#   bash scripts/ssi-did-key-demo.sh
#   KEYTYPE=ed25519 KC_URL=https://kc.example REALM=myrealm bash scripts/ssi-did-key-demo.sh

set -euo pipefail

KC_URL="${KC_URL:-http://localhost:8080}"
REALM="${REALM:-master}"
KEYTYPE="${KEYTYPE:-p256}"   # p256 (zDn…, ES256) or ed25519 (z6Mk…, EdDSA)

for t in curl jq node; do command -v "$t" >/dev/null || { echo "$t is required"; exit 1; }; done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/mint.mjs" <<'NODE'
import crypto from 'node:crypto';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const base58 = buf => { let n = BigInt('0x' + (Buffer.from(buf).toString('hex') || '0')), s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = '1' + s; else break; } return s; };
const b64 = s => Buffer.from(s).toString('base64url');

const keyType = process.env.KEYTYPE || 'p256';
let did, privateKey, alg;
if (keyType === 'ed25519') {
  const kp = crypto.generateKeyPairSync('ed25519'); privateKey = kp.privateKey; alg = 'EdDSA';
  const raw = Buffer.from(kp.publicKey.export({ format: 'jwk' }).x, 'base64url'); // 32 raw bytes
  did = 'did:key:z' + base58(Buffer.concat([Buffer.from([0xed, 0x01]), raw]));    // multicodec 0xed01
} else {
  const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }); privateKey = kp.privateKey; alg = 'ES256';
  const jwk = kp.publicKey.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x, 'base64url'), y = Buffer.from(jwk.y, 'base64url');
  const compressed = Buffer.concat([Buffer.from([(y[y.length - 1] & 1) ? 0x03 : 0x02]), x]); // SEC1 compressed
  did = 'did:key:z' + base58(Buffer.concat([Buffer.from([0x80, 0x24]), compressed]));         // multicodec 0x1200
}

const now = Math.floor(Date.now() / 1000);
const signingInput = b64(JSON.stringify({ alg, typ: 'JWT' })) + '.' +
  b64(JSON.stringify({ sub: did, iss: did, client_id: did, aud: ['https://as.example'], iat: now, exp: now + 300 }));
const sig = (alg === 'EdDSA')
  ? crypto.sign(null, Buffer.from(signingInput), privateKey)
  : crypto.sign('sha256', Buffer.from(signingInput), { key: privateKey, dsaEncoding: 'ieee-p1363' });
process.stdout.write(signingInput + '.' + sig.toString('base64url'));
NODE

JWT=$(KEYTYPE="$KEYTYPE" node "$WORK/mint.mjs")
printf '\n\033[1;36m== minted a %s did:key self-signed JWT\033[0m\n%s\n' "$KEYTYPE" "$JWT"

printf '\n\033[1;36m== verifying at %s\033[0m\n' "$KC_URL/realms/$REALM/lws-ssi-did-key/verify"
RESULT=$(curl -sS -X POST "$KC_URL/realms/$REALM/lws-ssi-did-key/verify" --data-urlencode "credential=$JWT")
echo "$RESULT" | jq .

if [ "$(printf '%s' "$RESULT" | jq -r '.valid // false')" = true ]; then
  printf '\n\033[1;36m== PASS\033[0m\n'
  echo "The did:key carries its own key, so any LWS server can verify this with no prior setup:"
  echo "    curl https://pod.example/ -H \"Authorization: Bearer \$JWT\""
else
  printf '\033[1;31mFAIL — see errors above\033[0m\n' >&2; exit 1
fi
