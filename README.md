# lws-authn — Keycloak providers for LWS authentication suites

A [Keycloak](https://www.keycloak.org/) **26.7.0** extension implementing **all four** authentication
suites of the W3C [Linked Web Storage (LWS)](https://www.w3.org/TR/lws10-core/) 1.0 protocol, in which
a **signed token bound to an identity** is used as an authentication credential:

- [**OpenID Connect**](https://w3c.github.io/lws-protocol/lws10-authn-openid/) — Keycloak is the
  OpenID Provider; the ID Token's `sub` is a WebID whose controlled identifier document (CID) names
  this Keycloak as its `OpenIdProvider` service.
- [**Self-signed Identity (Controlled Identifiers)**](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/) —
  an agent self-signs a JWT (`sub == iss == client_id`) with a key published as a `JsonWebKey` in its
  own CID.
- [**SAML 2.0**](https://w3c.github.io/lws-protocol/lws10-authn-saml/) — the credential is a signed
  SAML 2.0 `<Response>` whose `<NameID>` is the subject; trust in the IdP is established **out of band**.
- [**Self-signed `did:key`**](https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/) — an agent
  self-signs a JWT whose `sub` is a `did:key` that **embeds the public key** in the identifier itself;
  the verifier decodes the key directly, with nothing to dereference.

The OpenID and self-signed-CID suites dereference the subject's
[Controlled Identifier Document](https://www.w3.org/TR/cid-1.0/) and use **Apache Jena 6.1.0** for RDF;
SAML uses Keycloak's SAML library for XML signature validation; `did:key` is pure JDK crypto.

---

## Authentication suites

| Suite | Keycloak's role | Credential | How the verifier gets the key | Endpoint | Token type URI |
|-------|-----------------|------------|-------------------------------|----------|----------------|
| OpenID Connect | OP + CID host + verifier | ID Token (JWT); `sub` = WebID | OIDC Discovery on `iss` (found via the CID service) | `/realms/{realm}/lws` | `…token-type:id_token` |
| Self-signed CID | CID host + verifier | self-issued JWT; `sub`==`iss`==`client_id` | `publicKeyJwk` in the subject's CID, by `kid` | `/realms/{realm}/lws-ssi-cid` | `…token-type:jwt` |
| SAML 2.0 | SAML IdP + verifier | signed SAML `<Response>`; subject = `<NameID>` | **out-of-band** IdP certificate | `/realms/{realm}/lws-saml` | `…token-type:saml2` |
| Self-signed `did:key` | verifier only | self-issued JWT; `sub` = `did:key` | **decoded from the `did:key`** identifier itself | `/realms/{realm}/lws-ssi-did-key` | `…token-type:jwt` |

The suites are independent; deploy the single JAR and use any of them.

## What it provides

**OpenID Connect suite**

| Component | Keycloak SPI | Purpose |
|-----------|--------------|---------|
| `openid.LWSSubMapper` | `ProtocolMapper` (OIDC) | Sets `sub` to the user's WebID so ID Tokens are usable as LWS credentials. |
| `openid.resource.LWSResourceProvider` | `RealmResourceProvider` (`lws`) | Serves the CID (with the `OpenIdProvider` service) and a credential verifier. |
| `openid.verify.LWSCredentialVerifier` | — | Dereference `sub` → locate service → OIDC discovery → validate JWT. |

**Self-signed CID suite**

| Component | Keycloak SPI | Purpose |
|-----------|--------------|---------|
| `ssicid.resource.SsiCidResourceProvider` | `RealmResourceProvider` (`lws-ssi-cid`) | Serves the CID publishing the user's public key(s) as `authentication` methods, and a verifier. |
| `ssicid.verify.SelfSignedCidVerifier` | — | Check `sub==iss==client_id` → dereference `sub` → select key by `kid` → validate signature. |
| `ssicid.cid.SelfSignedControlledIdentifierDocument` | — | Builds the CID with `publicKeyJwk` verification methods. |

**SAML 2.0 suite**

| Component | Keycloak SPI | Purpose |
|-----------|--------------|---------|
| `saml.resource.SamlResourceProvider` | `RealmResourceProvider` (`lws-saml`) | Verifies a signed SAML 2.0 Response against a supplied (out-of-band) IdP certificate. |
| `saml.verify.SamlCredentialVerifier` | — | Validate the XML signature → read `<NameID>`/`<Issuer>` → enforce the validity window and audience. |

**Self-signed `did:key` suite**

| Component | Keycloak SPI | Purpose |
|-----------|--------------|---------|
| `ssididkey.resource.DidKeyResourceProvider` | `RealmResourceProvider` (`lws-ssi-did-key`) | Verifies a self-issued `did:key` JWT. |
| `ssididkey.verify.SelfSignedDidKeyVerifier` | — | Check `sub==iss==client_id` is a `did:key` → decode the key from it → validate signature. |
| `ssididkey.DidKey` | — | did:key codec (multibase base58btc + multicodec); decodes Ed25519 and P-256 keys, pure JDK. |

The OpenID and self-signed-CID suites serialize CIDs with Jena as JSON-LD / Turtle / N-Triples / RDF/XML.

---

## Build

Requires JDK 21+ and Maven. (The build compiles to Java 21 bytecode so the provider loads in
Keycloak's runtime; a newer build JDK such as 25 is fine.)

```bash
mvn clean package
```

This produces a single, self-contained provider JAR: **`target/lws-authn-0.1.0.jar`**. Apache Jena and
its dependencies are shaded in, and `commons-codec` is relocated so Jena binds to the version it needs
(≥ 1.19, for `MurmurHash3`) regardless of the older copy Keycloak ships. Keycloak's own SAML and crypto
libraries are used at `provided` scope (they are part of the server runtime).

## Deploy

Keycloak loads provider JARs from its `providers/` directory.

```bash
# from the project root, with $KC_HOME pointing at your Keycloak 26.7.0 install
cp target/lws-authn-0.1.0.jar "$KC_HOME/providers/"

"$KC_HOME/bin/kc.sh" build      # re-augment with the new provider
"$KC_HOME/bin/kc.sh" start      # or start-dev
```

On Windows use `kc.bat`. After `kc.sh build`, the startup log lists the registered providers; you
should see the `lws`, `lws-ssi-cid`, `lws-saml` and `lws-ssi-did-key` realm resources and the
`lws-webid-sub-mapper` protocol mapper.

---

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
[Securing the verify endpoints](#securing-the-verify-endpoints).

Walkthrough + runnable demo: **[`docs/walkthrough-openid.md`](docs/walkthrough-openid.md)** /
**[`scripts/lws-demo.sh`](scripts/lws-demo.sh)** (`bash scripts/lws-demo.sh`).

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
methods; `POST …/lws-ssi-cid/verify` validates a self-issued JWT (reject `none`; enforce
`sub==iss==client_id`; dereference `sub`; select key by `kid`; validate signature; check expiry +
audience).

Walkthrough + runnable demo: **[`docs/walkthrough-ssi-cid.md`](docs/walkthrough-ssi-cid.md)** /
**[`scripts/ssi-cid-demo.sh`](scripts/ssi-cid-demo.sh)**.

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

Guide: **[`docs/walkthrough-saml.md`](docs/walkthrough-saml.md)** (there is no shell demo — producing a
signed SAML Response requires a SAML login flow).

---

## Self-signed `did:key` suite

The most self-contained suite: the subject is a `did:key` identifier that **embeds the public key**
(multibase base58btc + multicodec), so there is no hosting, no dereferencing, and no realm setup — the
verifier decodes the key from the identifier and validates the self-signed JWT. Supported key types:
**Ed25519** (`did:key:z6Mk…`, EdDSA) and **P-256** (`did:key:zDn…`, ES256).

`POST …/lws-ssi-did-key/verify` — validates a self-issued `did:key` JWT (reject `none`; enforce
`sub==iss==client_id` is a `did:key`; decode the key from the identifier; check the JWT `alg` matches
the key type; validate the signature; check expiry + audience):

```json
{ "valid": true, "subject": "did:key:zDnaerx9…", "keyType": "P-256",
  "checks": { "signingAlgorithmNotNone": true, "selfIssued": true, "subjectIsDidKey": true,
              "keyDecodedFromDid": true, "algorithmMatchesKey": true, "signatureValid": true,
              "notExpired": true, "audiencePresent": true } }
```

Walkthrough + runnable demo (mints a `did:key` and verifies it):
**[`docs/walkthrough-ssi-did-key.md`](docs/walkthrough-ssi-did-key.md)** /
**[`scripts/ssi-did-key-demo.sh`](scripts/ssi-did-key-demo.sh)**.

---

## Security

The verifiers are hardened against the classic attacks on credential-verification code. These
behaviours are covered by tests — `mvn test` for the unit tests, `mvn verify` for the container IT:

- **SSRF.** The OpenID and self-signed-CID verifiers dereference URLs taken from the credential
  (`sub`, `iss`, `jwks_uri`). Before each fetch,
  [`SsrfGuard`](src/main/java/com/ebremer/lws/authn/net/SsrfGuard.java) rejects non-`http(s)` schemes
  and any host that resolves to a loopback / private / link-local / reserved address (including the
  `169.254.169.254` cloud-metadata endpoint). Legitimate internal targets are opt-in via a
  comma-separated allow-list — system property `lws.authn.allowedInternalHosts` or environment
  variable `LWS_AUTHN_ALLOWED_INTERNAL_HOSTS`.
  - The check is part of **name resolution**, not a separate step before it: the guard is installed as
    the DNS resolver of the HTTP client the verifiers use, so the addresses it approves are exactly the
    addresses the connection manager connects to. There is no second lookup for a hostile name server
    to poison, which is what closes the DNS-rebinding window.
  - That client also has **redirect following disabled**. Keycloak's shared client happens to disable
    redirects by default too (`spi-connections-http-client-default-allow-redirects`, default `false`),
    but that is a deployment setting one flag away from letting a `302` walk past the guard — so the
    verifiers do not depend on it.
  - **Important:** if this Keycloak hosts its own controlled identifier documents on a loopback or
    internal address — so the OpenID verifier dereferences *itself* — you **must** allow-list that
    host, or OpenID `/verify` is blocked.
  - A host that fails repeatedly is short-circuited for a few seconds, so a dead or hostile target
    cannot be used to make this server spend five seconds per request on the caller's behalf.
- **Information disclosure.** A verify response never reflects an upstream status code, a resolved
  address or a raw exception message. Rejections carry a `traceId`; the detail is in the server log at
  `DEBUG` under that id.
- **Private key material.** The self-signed-CID endpoint publishes only the public members of a
  registered JWK, and refuses to publish a value carrying private key material at all (CID 1.0: a
  `publicKeyJwk` map "MUST NOT include any members of the private information class").
- **SAML signature wrapping (XSW).** The SAML verifier validates the signature and then reads claims
  **only from the cryptographically-covered assertion**, located by precise direct-child navigation
  (never a document-wide `getElementsByTagName` an injected element could win). It additionally
  requires the signature to reference the signed element by its own `ID`, and a signed Response to
  contain exactly one assertion. An injected, unsigned assertion is ignored.
- **XXE.** SAML XML is parsed with a locally-configured parser that **disallows DTDs** and disables
  external entities, independent of any caller/library parser configuration.

---

## Securing the verify endpoints

The four `…/verify` endpoints are **authenticated by default**. Verification is expensive out of
proportion to the request that triggers it: for the OpenID and self-signed-CID suites a single POST
makes this server dereference a URL the caller chose, run OpenID Connect Discovery against it and
fetch its JWKS — all *before* the credential's signature is known good, because that is the order the
specification's cold-trust algorithm requires. Open to anonymous callers that is request
amplification, a network-probe oracle and a cheap denial of service.

| Setting | `Config.Scope` key | System property | Environment variable | Default |
|---|---|---|---|---|
| Mode | `access` | `lws.authn.verify.access` | `LWS_AUTHN_VERIFY_ACCESS` | `bearer` |
| Shared secret | `secret` | `lws.authn.verify.secret` | `LWS_AUTHN_VERIFY_SECRET` | — |
| Required realm role | `role` | `lws.authn.verify.role` | `LWS_AUTHN_VERIFY_ROLE` | — |
| Requests per minute, per caller | `rate-limit` | `lws.authn.verify.rateLimit` | `LWS_AUTHN_VERIFY_RATE_LIMIT` | `60` |

- **`bearer`** (default) — the caller presents a Keycloak access token for the realm. Set `role` to
  additionally require a realm role.
- **`secret`** — the caller presents a pre-shared secret as `Authorization: Bearer <secret>`, for a
  verifier that is not a Keycloak client. Configuring `secret` mode with no secret falls back to
  `bearer`; it never fails open.
- **`public`** — no caller authentication. This is the pre-existing behaviour, and is now opt-in.

> **The `Authorization` header changed meaning.** In `bearer` and `secret` mode it carries the
> **caller's** credential, so the credential being verified must be sent as the `credential` form
> parameter. Only in `public` mode does `Authorization: Bearer …` still fall back to meaning "the
> credential to verify". If you were relying on that form, either send the credential in the body or
> set the mode to `public` explicitly.

Rate limiting applies in every mode, including `public`, and is enforced before the caller is
authenticated. Set `rate-limit` to `0` to turn it off. A refusal is a `401`/`403`/`429` carrying a
`WWW-Authenticate` challenge, which is what distinguishes "you may not call this endpoint" from a
`401` meaning "the credential you asked me to check is not valid".

Set the mode with either `kc.sh build --spi-realm-restapi-extension--lws--access=public` (repeat per
provider id: `lws`, `lws-ssi-cid`, `lws-saml`, `lws-ssi-did-key`) or, with no rebuild, the environment
variable `LWS_AUTHN_VERIFY_ACCESS=public`.

---

## Notes & limitations

- **Key/identity hosting.** The OpenID and self-signed-CID `cid/{userId}` endpoints serve
  Keycloak-hosted identifiers; private keys never reach Keycloak (only public JWKs are registered). The
  SAML and `did:key` suites host nothing.
- **SAML trust is out-of-band.** The verifier requires the trusted IdP certificate as input; it
  validates the XML signature, the `<Conditions>` window (±60 s skew) and the audience, but does not
  fetch metadata or build a trust chain.
- **`did:key` key types.** Ed25519 and P-256 are supported; secp256k1 and other multicodecs are not.
  No BouncyCastle is used (works under default and FIPS Keycloak crypto).
- **`frontendUrl`.** Derived identifiers and served documents are built from the realm front-end URL;
  set it (or run behind a stable hostname) so they stay consistent and publicly dereferenceable.
- **Verifier networking & syntaxes.** OpenID/self-signed-CID verification dereferences `sub` (and, for
  OpenID, performs Discovery). Verifiers request Turtle first; Turtle / N-Triples / RDF/XML are parsed
  with Jena RIOT, JSON-LD is interpreted directly for the standardized CID shape (exotic framings are
  not expanded).
- **Audience / token exchange.** Restrict credential audiences (Resource Indicators, RFC 8707) and use
  OAuth 2.0 Token Exchange (RFC 8693) with each suite's token type URI where appropriate.

## Layout

```
src/main/java/com/ebremer/lws/authn/
  openid/                                       OpenID Connect suite
    LWSConstants, LWSSubMapper                  vocabulary + sub→WebID protocol mapper
    cid/ControlledIdentifierDocument            CID builder (OpenIdProvider service)
    resource/LWSResourceProvider(.Factory)      JAX-RS endpoints, mount id "lws"
    verify/LWSCredentialVerifier, VerificationResult
  ssicid/                                       Self-signed CID suite
    SsiCidConstants
    cid/SelfSignedControlledIdentifierDocument  CID builder (publicKeyJwk methods)
    resource/SsiCidResourceProvider(.Factory)   mount id "lws-ssi-cid"
    verify/SelfSignedCidVerifier, SsiCidVerificationResult
  saml/                                         SAML 2.0 suite
    SamlConstants
    resource/SamlResourceProvider(.Factory)     mount id "lws-saml"
    verify/SamlCredentialVerifier, SamlVerificationResult
  ssididkey/                                    Self-signed did:key suite
    DidKeyConstants, DidKey                     did:key codec (base58btc + multicodec, pure JDK)
    resource/DidKeyResourceProvider(.Factory)   mount id "lws-ssi-did-key"
    verify/SelfSignedDidKeyVerifier, DidKeyVerificationResult
src/main/resources/META-INF/services/           SPI registrations (mapper + four resource factories)
```
