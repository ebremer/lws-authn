---
title: Self-signed CID
parent: Walkthroughs
nav_order: 2
---

# Walkthrough: a self-signed LWS identity with Keycloak

This is the companion to the [OpenID Connect walkthrough](walkthrough-openid.md) for the
[**Self-signed Identity (Controlled Identifiers) Authentication Suite**](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/).
Here the agent signs its own credential — Keycloak never issues a token. Keycloak's job is only to
**publish the agent's public key** in a controlled identifier document and to **verify** credentials.

## The cast

| Party | Role |
|-------|------|
| **The agent** | Holds an EC private key and signs its own JWTs. |
| **Keycloak + `lws-authn`** | Hosts the agent's controlled identifier document (its public key) and offers a verifier. It is *not* an OpenID Provider here. |
| **An LWS server** | The verifier — dereferences the credential's `sub`, selects the key by `kid`, validates the signature. |

**The idea:** the credential is self-issued (`sub == iss == client_id`), and trust comes entirely from
the subject's own document, which publishes the signing key as an `authentication` verification method.
A verifier needs no prior relationship with anyone — it fetches the key from the identity itself.

For that to mean anything the document has to be CID-conformant, and the verifier holds it to that: an
`id` equal to the subject, and the key listed under `authentication` — embedded there, or defined under
`verificationMethod` and referenced — with an `id` in the document, a `type` of `JsonWebKey` or
`Multikey`, and a `controller` equal to the subject. A method the subject does not control is not a key
it may authenticate with, however it got into the document, and neither is one the document only lists
for some other purpose, or has marked `revoked` or let `expire`. The JWT must also name its key with
`kid` and carry both `iat` and `exp`.

> **The identity does not have to live in Keycloak, or at an HTTPS URL.** This walkthrough uses a
> Keycloak-hosted document, but the suite "is designed to work with subject identifiers that use HTTPS
> URIs as well as DID URIs". The same `…/lws-ssi-cid/verify` endpoint accepts a `did:key` — resolved
> locally from the key it embeds — and a `did:web`, whose document it fetches from
> `https://<domain>/…/did.json`. Set `sub`, `iss` and `client_id` to the DID and `kid` to the
> verification method id (`did:key:z…#z…`, `did:web:example.com#key-1`); see
> the [`did:key` walkthrough](walkthrough-ssi-did-key.md) and [*DID subjects*](suites.md#did-subjects).

---

## Prerequisites

- Keycloak **26.7.4** with the `lws-authn` provider deployed — see [Build and deploy](build.md).
- `curl`, `jq`, and `openssl`.
- For a quick local run: `docker compose up --build --wait` in a checkout — see
  [Run with Docker](build.md#run-with-docker) — which serves `http://localhost:8080` with admin/admin
  and the `lws-demo` realm already imported. Or `bin/kc.sh start-dev` (admin/admin) at
  `http://localhost:8080`.

---

## Fast path — one script

Run [`scripts/ssi-cid-demo.sh`](https://github.com/ebremer/lws-authn/blob/master/scripts/ssi-cid-demo.sh)
from a checkout of the repository:

```bash
bash scripts/ssi-cid-demo.sh
```

It generates a keypair, registers the public JWK on a user, dereferences the published document, mints
a self-issued ES256 JWT, and runs it through `/lws-ssi-cid/verify`, ending in `valid: true`.

The rest is the same thing by hand.

---

## Manual path

### 1. Allow *admin-managed* unmanaged attributes

> **Running the Docker setup?** Its `lws-demo` realm is already configured this way, and has the user
> `alice`; go on to step 2.

Keycloak 26 rejects undeclared user attributes by default, so the public key (`lws_jwk`) would be
dropped. Allow them once per realm — as **`ADMIN_EDIT`**: *Realm settings → User profile → (kebab) →
Unmanaged attributes → Only administrators can write*, or via the API:

```bash
curl -s -H "Authorization: Bearer $ADMIN" "$KC/admin/realms/$REALM/users/profile" \
  | jq '.unmanagedAttributePolicy="ADMIN_EDIT"' \
  | curl -s -X PUT "$KC/admin/realms/$REALM/users/profile" \
      -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -d @-
```

> **Do not use `ENABLED` here.** `ENABLED` lets the *end user* manage unmanaged attributes, and
> `lws_jwk` is the signing key their own controlled identifier document publishes. A user who can
> write it can register any key against their identity and sign credentials for it. The same applies
> to any attribute you point the OpenID suite's **LWS WebID Subject** mapper at: it becomes the
> credential's `sub`, so a user who can write it can claim any WebID.

Only the public half of a key is ever served. A `lws_jwk` value containing `d`, `p`, `q`, `dp`, `dq`,
`qi`, `k` or `oth`, or one whose `kty` is `oct`, is refused outright and logged — never published.

### 2. Generate the agent's keypair and its public JWK

```bash
openssl ecparam -name prime256v1 -genkey -noout -out priv.pem      # keep this private
# derive the public JWK x/y (last 65 bytes of the DER are 04||X||Y)
openssl ec -in priv.pem -pubout -outform DER 2>/dev/null | tail -c 65 > point.bin
b64u() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
X=$(dd if=point.bin bs=1 skip=1  count=32 2>/dev/null | b64u)
Y=$(dd if=point.bin bs=1 skip=33 count=32 2>/dev/null | b64u)
JWK="{\"kid\":\"agent-key-1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"$X\",\"y\":\"$Y\"}"
```

### 3. Register the public JWK on the user (`lws_jwk`)

Set the `lws_jwk` user attribute to that JWK (Users → alice → Attributes, or the admin API). Multiple
values publish multiple keys (useful for rotation). The agent's identifier is then
`{issuer}/lws-ssi-cid/cid/{userId}`.

### 4. Dereference the controlled identifier document

```bash
curl -s -H 'Accept: text/turtle' "$KC/realms/$REALM/lws-ssi-cid/cid/$USER_UUID"
```

```turtle
<…/lws-ssi-cid/cid/2b8a…e1>
    <https://w3id.org/security#authenticationMethod> <…/lws-ssi-cid/cid/2b8a…e1#agent-key-1> .
<…/lws-ssi-cid/cid/2b8a…e1#agent-key-1>
    a <https://w3id.org/security#JsonWebKey> ;
    <https://w3id.org/security#controller> <…/lws-ssi-cid/cid/2b8a…e1> ;
    <https://w3id.org/security#publicKeyJwk> "{…JWK…}"^^rdf:JSON .
```

(JSON-LD via `Accept: application/ld+json` gives the compact `authentication` / `publicKeyJwk` form.)

### 5. Mint a self-issued JWT

`sub`, `iss` and `client_id` are all the document URL; sign with the private key (ES256):

```
header  = {"alg":"ES256","kid":"agent-key-1","typ":"JWT"}
payload = {"sub":"<docUrl>","iss":"<docUrl>","client_id":"<docUrl>",
           "aud":["https://as.example"],"iat":<now>,"exp":<now+300>}
```

Sign `base64url(header) + "." + base64url(payload)`; ES256 needs the signature as raw `R‖S`
(two 32-byte integers), which is what `scripts/ssi-cid-demo.sh` produces from OpenSSL's DER output.

### 6. Verify

```bash
curl -s -X POST "$KC/realms/$REALM/lws-ssi-cid/verify" \
  -H "Authorization: Bearer $CALLER_ACCESS_TOKEN" \
  --data-urlencode "credential=$JWT" | jq
```

> `Authorization` identifies **you**, the caller: the `…/verify` endpoints are authenticated by
> default. The credential being checked always travels in the request body. See
> [Securing the verify endpoints](configuration.md#securing-the-verify-endpoints).

```json
{
  "valid": true,
  "subject": "…/lws-ssi-cid/cid/2b8a…e1",
  "checks": {
    "signingAlgorithmNotNone": true,
    "selfIssued": true,
    "subjectDereferenced": true,
    "verificationMethodFound": true,
    "signatureValid": true,
    "notExpired": true,
    "audiencePresent": true
  }
}
```

### 7. Present it to an LWS server

```bash
curl https://pod.example/agent/ -H "Authorization: Bearer $JWT"
```

The server dereferences `sub`, selects the verification method whose key matches the JWT `kid`,
validates the signature, and authenticates the request as that identifier — no configuration of
Keycloak required, because the identity carries its own key.

---

## Notes

- **The private key never reaches Keycloak.** Only the public JWK is registered; Keycloak hosts it and
  verifies, but cannot mint credentials for the agent.
- **Key rotation** — register several JWKs (each with a distinct `kid`); the document lists them all,
  and a verifier selects by the JWT's `kid`.
- **`sub` must equal the document URL.** Because the verifier looks up the key under the dereferenced
  subject, the self-issued `sub`/`iss`/`client_id` must be exactly the document's `id` (the demo reads
  it back from the document to be sure).
- **Audience / token type.** The credential carries the suite's token type URI
  `urn:ietf:params:oauth:token-type:jwt` when exchanged; the verifier requires an `aud`. Restrict it to
  the target server in production.
