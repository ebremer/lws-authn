---
title: Suites
parent: Reference
nav_order: 1
---

# Suites

How each suite is configured, and what its endpoints take. The [walkthroughs](walkthroughs.md) do the
same things step by step.

## OpenID Connect suite

### Configure

1. **Sign-in / client.** Use any OIDC client as usual. The realm's token signing key must not be
   `none` (Keycloak's default RS256 is fine).
2. **Add the LWS WebID Subject mapper.** *Clients → your client → Client scopes →
   `<client>-dedicated` → Add mapper → By configuration → **LWS WebID Subject***.
   - **WebID user attribute** *(optional)* — a user attribute holding a WebID the user already owns.
     When empty, the `sub` becomes the Keycloak-hosted URL `{issuer}/lws/cid/{userId}`.
   - **Add to ID token / access token / userinfo** — default on. The ID Token is the LWS credential.

### Endpoints — `/realms/{realm}/lws`

`GET …/lws/cid/{userId}` serves the CID (content-negotiated JSON-LD / Turtle / N-Triples / RDF/XML)
with the `OpenIdProvider` service; `POST …/lws/verify` runs the full validation (dereference `sub` →
locate the service → OIDC discovery → validate signature):

```bash
curl -X POST https://keycloak.example/realms/myrealm/lws/verify \
  -H "Authorization: Bearer $CALLER_ACCESS_TOKEN" \
  --data-urlencode "credential=$ID_TOKEN"
```

`Authorization` carries **your** access token; the credential being verified goes in the body. See
[Securing the verify endpoints](configuration.md#securing-the-verify-endpoints).

Two optional parameters turn on the audience half of OpenID Connect Core §3.1.3.7, which the suite
incorporates by reference:

| Param | |
|---|---|
| `client_id` | your own client identifier. When given, `aud` must list it and `azp` must equal it (steps 3–5). |
| `audience` | an additional audience the credential must be restricted to, typically the authorization server. |

> LWS core §4.1 says a client identifier **SHOULD** be a URI. `lws-authn` requires `azp` to be present
> but does not require it to be a URI, so a conventional Keycloak client id verifies. Prefer a URI in
> production — see [*Known divergences*](COMPLIANCE.md#known-divergences-and-deliberate-choices) in the
> conformance statement.

Without them the credential is still validated — signature, issuer, expiry, and a required `azp` — but
nothing binds it to *you*, so a token minted for another relying party would pass. Supply them wherever
the result is treated as an authentication.

Walkthrough + runnable demo: **[OpenID Connect walkthrough](walkthrough-openid.md)** /
**[`scripts/lws-demo.sh`](https://github.com/ebremer/lws-authn/blob/master/scripts/lws-demo.sh)** (`bash scripts/lws-demo.sh`).

---

## Self-signed CID suite

Keycloak does **not** issue the credential — the agent does. Keycloak hosts the agent's public key so
verifiers can find it, and offers a verifier.

1. The agent generates a keypair, keeps the private key, and registers the **public** JWK on the user
   as the `lws_jwk` attribute. Its identifier is `{issuer}/lws-ssi-cid/cid/{userId}`.
   - Keycloak 26 drops undeclared attributes, so set the realm's unmanaged attribute policy to
     **`ADMIN_EDIT`** — *not* `ENABLED`. `ENABLED` lets the **end user** write `lws_jwk`, and a user
     who can register their own signing key can mint credentials for their own identity.
   - Only the public half is ever served: a `lws_jwk` value containing `d`, `p`, `q`, `dp`, `dq`,
     `qi`, `k` or `oth`, or a `kty` of `oct`, is refused outright and logged, never published.
2. The agent self-signs a JWT (`sub == iss == client_id ==` that identifier, header `kid` matching the
   key).

`GET …/lws-ssi-cid/cid/{userId}` serves the CID publishing the registered key(s) as `authentication`
methods; `POST …/lws-ssi-cid/verify` validates a self-issued JWT: reject `none` and any unsupported
`crit` header; enforce `sub == iss == client_id`; require a `kid`; dereference `sub` to a document
whose `id` **is** `sub`; select, by `kid`, a `JsonWebKey` or `Multikey` method the document's
`authentication` relationship names — embedded or by reference — that the subject **controls** and
that is neither revoked nor expired; pin the `alg` to that key; validate the signature; require `iat`
and `exp`; and check the audience.

Pass `audience=<authorization server>` to enforce the suite's "the `aud` claim MUST include the target
authorization server" — without it only the presence of an audience restriction can be checked.

The document a verifier dereferences must therefore be CID-conformant: an `id` equal to the subject,
and the key listed under `authentication` (CID 1.0 §2.3 — a key defined under `verificationMethod`
but named only by, say, `assertionMethod` cannot authenticate), with an `id` in that document, a
`type` of `JsonWebKey` or `Multikey`, and a `controller` equal to the subject. The documents this
provider serves already are.

### DID subjects

The suite "is designed to work with subject identifiers that use HTTPS URIs as well as DID URIs": a
DID document extends a controlled identifier document, so the same validation applies once the DID is
resolved. Two methods are resolved; any other is refused by name.

| Method | Resolution | Example `kid` |
|---|---|---|
| `did:key` | expanded locally into the did:key Method's document — one `Multikey` method, referenced from `authentication`. No network. Must be canonically encoded; Ed25519, P-256, P-384 or P-521. | `did:key:zDnae…#zDnae…` |
| `did:web` | `did:web:example.com` → `https://example.com/.well-known/did.json`; `did:web:example.com:u:bob` → `https://example.com/u/bob/did.json`; a port as `%3A`. Fetched through the same SSRF-guarded client as an HTTPS subject; a domain name only, never an IP address; the document's `id` must be the DID. | `did:web:example.com#key-1` |

A `kid` may name the method by its full identifier, as above, or by its fragment (`key-1` or
`#key-1`), or by its JWK's own `kid`. This suite requires one; for a `did:key` it is
`"kid": "<did>#<multibase>"`.

Walkthrough + runnable demo: **[Self-signed CID walkthrough](walkthrough-ssi-cid.md)** /
**[`scripts/ssi-cid-demo.sh`](https://github.com/ebremer/lws-authn/blob/master/scripts/ssi-cid-demo.sh)**;
for a `did:key` subject, **[`did:key` identity walkthrough](walkthrough-did-key.md)** /
**[`scripts/did-key-demo.sh`](https://github.com/ebremer/lws-authn/blob/master/scripts/did-key-demo.sh)**.

---

## SAML 2.0 suite

The credential is a signed SAML 2.0 `<Response>`; the subject is the `<NameID>`. Trust is **out of
band**: the verifier validates the assertion's XML signature against a pre-configured IdP certificate —
no CID and no discovery, so this suite uses neither Jena nor a CID endpoint.

Keycloak is a full SAML 2.0 IdP; to issue LWS SAML credentials, set up a SAML client and arrange for
the `<NameID>` to carry the user's WebID. The realm's SAML signing certificate is published at
`…/realms/{realm}/protocol/saml/descriptor`.

`POST …/lws-saml/verify` — validates a signed SAML Response. Supply the trusted IdP certificate (since
trust is out-of-band):

| Param | |
|---|---|
| `credential` | the SAML Response (raw XML or base64-encoded XML) |
| `certificate` | the trusted IdP signing certificate, PEM-encoded (required) |
| `audience` | optional audience the assertion must be restricted to |
| `allowExpiredCertificate` | `true` to accept an IdP certificate outside its own validity period. Off by default — an expired certificate is not a trust anchor. Only for offline analysis of an old credential. |

```bash
curl -X POST https://keycloak.example/realms/myrealm/lws-saml/verify \
  -H "Authorization: Bearer $CALLER_ACCESS_TOKEN" \
  --data-urlencode "credential=$SAML_RESPONSE" \
  --data-urlencode "certificate=$IDP_CERT_PEM" \
  --data-urlencode "audience=https://app.example/SAML"
```

The verifier additionally requires the Response's `<samlp:StatusCode>` to be
`…:status:Success`, exactly one bearer `<SubjectConfirmation>` whose `<SubjectConfirmationData>`
carries a `Recipient` (the LWS client identifier) and an unexpired `NotOnOrAfter`, and a signing
certificate that is inside its own validity period.

Guide: **[SAML 2.0 walkthrough](walkthrough-saml.md)** (there is no shell demo — producing a
signed SAML Response requires a SAML login flow).
