# lws-authn — Keycloak providers for LWS authentication suites

A [Keycloak](https://www.keycloak.org/) **26.7.3** extension implementing **all four** authentication
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
[Controlled Identifier Document](https://www.w3.org/TR/cid-1.0/) and use **Apache Jena 6.2.0** for RDF;
SAML uses Keycloak's SAML library for XML signature validation; `did:key` is pure JDK crypto.

### The other documents

| | |
|---|---|
| [`INSTALL.md`](INSTALL.md) | Deploying this on a server, start to finish. |
| [`COMPLIANCE.md`](COMPLIANCE.md) | **The conformance statement** — which normative requirements each suite enforces, which are deferred to the relying party, and what a `"valid": true` actually asserts. Read it before integrating. |
| [`CHANGELOG.md`](CHANGELOG.md) | What changed, and **what breaks on upgrade**. |
| [`SECURITY.md`](SECURITY.md) | Reporting a vulnerability, and what is deliberate rather than a bug. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Building, testing, and the conventions this codebase expects. |
| [`TODO.md`](TODO.md) | The backlog, as a review against the specifications — and the design history of everything already done. |
| [`docs/`](docs/) | A walkthrough per suite, each with a runnable demo script. |

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
| `ssididkey.DidKey` | — | did:key codec (multibase base58btc + multicodec); decodes Ed25519, P-256, P-384 and P-521 keys, pure JDK. |

The OpenID and self-signed-CID suites serialize CIDs with Jena as JSON-LD / Turtle / N-Triples / RDF/XML.

---

## Build

Requires JDK 21+ and Maven. (The build compiles to Java 21 bytecode so the provider loads in
Keycloak's runtime; a newer build JDK such as 25 is fine.)

```bash
mvn clean package
```

This produces a single, self-contained provider JAR: **`target/lws-authn-0.2.0.jar`**, plus a CycloneDX
SBOM (`target/bom.json`, `target/bom.xml`) listing exactly what is inside it and under what licence.

Apache Jena and its dependencies are shaded in. Where Jena and Keycloak want the same library, the
build picks one of two strategies deliberately, because the wrong one is a runtime failure either way:

| Situation | Treatment | Examples |
|---|---|---|
| Keycloak's copy satisfies Jena | `provided` — use the server's, bundle nothing | `slf4j-api`, `jcl-over-slf4j`, `jakarta.json`, `jspecify` |
| Jena needs a **newer** version than Keycloak ships | bundle Jena's version and **relocate** it | `commons-codec` 1.20 (vs 1.11), `titanium-json-ld` 1.7.0 (vs 1.3.3), `commons-collections4` 4.5.0 (vs 4.4), `caffeine` 3.2.4 (vs 3.2.3) |

Bundling an unrelocated second copy of a library the server already has puts two implementations of one
package on the classpath; marking one `provided` when Jena needs a newer version silently downgrades it.
The relocated versions are pinned explicitly, because Maven resolves the tie between Jena's and
Keycloak's copies by declaration order and would otherwise pick Keycloak's older one.

`mvn package` enforces this: `maven-enforcer-plugin` fails the build on duplicate classes among the
bundled artifacts, and the shade plugin's `artifactSet` excludes hold regardless of what Maven's scope
mediation decides. Keycloak's own SAML, crypto and HTTP libraries are `provided` — they are part of the
server runtime.

Getting this wrong does not fail a unit test: it fails when Jena loads inside Keycloak. `mvn verify`
runs `LwsAuthIT`, which deploys the shaded JAR into a real Keycloak container and exercises RDF
serving, parsing and SPARQL — run it after touching dependencies.

### Tests

`mvn test` runs 144 unit tests. `mvn verify` additionally runs 23 in `LwsAuthIT`, which needs Docker
and is skipped without it.

**`LwsAuthIT` binds host port 8080 and cannot run in parallel with itself.** The OpenID verifier
dereferences its own issuer, so that URL has to resolve to Keycloak both from the test JVM and from
inside the container, and `http://localhost:8080` bound straight through is the only spelling that
does. The suite checks the port first and says so rather than timing out; the reasoning, and why a
random port is not worth what it costs, is in the `LwsAuthIT` class javadoc.

Roughly half the integration tests assert a *rejection* rather than an acceptance. That is deliberate:
a verifier that wrongly rejects gets reported by its users, and one that wrongly accepts does not, so
the failure branches are where a bug goes unnoticed. A host-side fixture server plays a third-party
OpenID Provider — controlled identifier document, discovery document, JWKS — and each test breaks
exactly one of the three, asserting *which* check fails rather than merely that the credential was
refused.

CI (`.github/workflows/ci.yml`) runs that on JDK 21, builds again on JDK 25 and asserts the class files
are still Java 21, and runs CodeQL. Actions are pinned by commit SHA; Dependabot proposes the bumps.

## Deploy

Keycloak loads provider JARs from its `providers/` directory.

```bash
# from the project root, with $KC_HOME pointing at your Keycloak 26.7.3 install
cp target/lws-authn-0.2.0.jar "$KC_HOME/providers/"

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

Two optional parameters turn on the audience half of OpenID Connect Core §3.1.3.7, which the suite
incorporates by reference:

| Param | |
|---|---|
| `client_id` | your own client identifier. When given, `aud` must list it and `azp` must equal it (steps 3–5). |
| `audience` | an additional audience the credential must be restricted to, typically the authorization server. |

> LWS core §4.1 says a client identifier **SHOULD** be a URI. `lws-authn` requires `azp` to be present
> but does not require it to be a URI, so a conventional Keycloak client id verifies. Prefer a URI in
> production — see [`COMPLIANCE.md`](COMPLIANCE.md) § *Known divergences*.

Without them the credential is still validated — signature, issuer, expiry, and a required `azp` — but
nothing binds it to *you*, so a token minted for another relying party would pass. Supply them wherever
the result is treated as an authentication.

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
methods; `POST …/lws-ssi-cid/verify` validates a self-issued JWT: reject `none` and any unsupported
`crit` header; enforce `sub == iss == client_id`; require a `kid`; dereference `sub` to a document
whose `id` **is** `sub`; select a `JsonWebKey` method that document's subject **controls**; pin the
`alg` to that key; validate the signature; require `iat` and `exp`; and check the audience.

Pass `audience=<authorization server>` to enforce the suite's "the `aud` claim MUST include the target
authorization server" — without it only the presence of an audience restriction can be checked.

The document a verifier dereferences must therefore be CID-conformant: an `id` equal to the subject,
and verification methods carrying `id`, `type: JsonWebKey` and a `controller` equal to the subject.
The documents this provider serves already are.

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
**Ed25519** (`did:key:z6Mk…`, EdDSA), **P-256** (`did:key:zDn…`, ES256), **P-384** (ES384) and
**P-521** (ES512).

The encoding must be canonical: a decoded key is re-encoded and must reproduce the identifier exactly.
A `did:key` *is* its key, so allowing two spellings of one key would let a single agent present itself
as two subjects.

`POST …/lws-ssi-did-key/verify` — validates a self-issued `did:key` JWT: reject `none` and any
unsupported `crit` header; enforce `sub == iss == client_id` is a **canonically encoded** `did:key`;
decode the key from the identifier; check the JWT `alg` matches the key type; validate the signature;
require `iat` and `exp`; check the audience. Pass `audience=<authorization server>` to require that the
credential names it:

```json
{ "valid": true, "subject": "did:key:zDnaerx9…", "client": "did:key:zDnaerx9…",
  "keyType": "P-256", "tokenType": "urn:ietf:params:oauth:token-type:jwt",
  "checks": { "signingAlgorithmNotNone": true, "noUnsupportedCriticalHeaders": true,
              "selfIssued": true, "subjectIsDidKey": true, "keyDecodedFromDid": true,
              "algorithmMatchesKey": true, "signatureValid": true, "notExpired": true,
              "issuedAtPresent": true, "audiencePresent": true } }
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
- **The `cid/{userId}` endpoints are unauthenticated, deliberately.** A controlled identifier is a URL
  other people dereference — that is what makes it an identifier rather than a local user record — and
  a verifier meets the subject there before any trust exists in either direction, so there is no
  credential it could present. What that costs is enumeration, which is bounded rather than closed: the
  identifiers are Keycloak user ids (random UUIDs, not guessable and not meaningful), every answer —
  document, `404`, `406`, `429` — is the same media type with the same body shape so nothing but the
  status distinguishes them, and a rate limit (`cid-rate-limit`, default 600/minute per caller) makes
  scraping slow. Set `enabled=false` for a deployment that does not want to host identifiers at all.
- **Unrecognised syntaxes are refused, not guessed.** A dereferenced document that declares a content
  type which is not an RDF syntax this verifier reads is rejected by name, rather than handed to the
  Turtle parser to fail with a misleading error. Only a document declaring nothing at all falls back to
  Turtle, the syntax the verifiers ask for first.

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
authenticated. Set `rate-limit` to `0` to turn it off.

Set the mode with either `kc.sh build --spi-realm-restapi-extension--lws--access=public` (repeat per
provider id: `lws`, `lws-ssi-cid`, `lws-saml`, `lws-ssi-did-key`) or, with no rebuild, the environment
variable `LWS_AUTHN_VERIFY_ACCESS=public`.

### What each status means

A `/verify` status is about **the request**, never about the credential in it. The credential's verdict
is in the body:

| Status | Meaning |
|---|---|
| `200` | The request was answered. Read `valid` — `true` or `false`. |
| `400` | The request could not be read: a missing or unparseable parameter. |
| `401` / `403` | **You** may not use this endpoint. Carries a `WWW-Authenticate` challenge (RFC 9110 §15.5.2). |
| `404` | This suite is not enabled on this realm. |
| `429` | Rate limited; retry shortly. |

> **A rejected credential is a `200` with `"valid": false`.** Until this release it was a bare `401`
> with no challenge — which RFC 9110 §15.5.2 forbids, and which said the wrong thing anyway: the
> request *was* authorized, and the server answered it. A client that treated any non-`200` as
> "endpoint unavailable" now sees the verdict it was asking for. Check `valid`, not the status.

Every non-`200` carries `application/json` of one shape — `{"error": …, "error_description": …}` —
whichever endpoint and whichever status produced it.

---

## Configuration reference

Every setting is read from the provider's `Config.Scope` first, then a system property, then an
environment variable, then a compiled-in default. `Config.Scope` is the supported surface
(`kc.sh build --spi-realm-restapi-extension--<provider>--<key>=<value>`, where `<provider>` is `lws`,
`lws-ssi-cid`, `lws-saml` or `lws-ssi-did-key`) and the only one that can differ per provider; the
environment variable is what a container deployment can set without rebuilding the image.

**Per provider:**

| Setting | Scope key | System property | Environment variable | Default |
|---|---|---|---|---|
| Serve this suite at all | `enabled` | `lws.authn.enabled` | `LWS_AUTHN_ENABLED` | `true` |
| Audience to require when the request names none | `audience` | `lws.authn.audience` | `LWS_AUTHN_AUDIENCE` | — |
| `Cache-Control: max-age` on a served CID | `cid-cache-seconds` | `lws.authn.cid.cacheSeconds` | `LWS_AUTHN_CID_CACHE_SECONDS` | `300` |
| CID requests per minute, per caller | `cid-rate-limit` | `lws.authn.cid.rateLimit` | `LWS_AUTHN_CID_RATE_LIMIT` | `600` |

Plus the four verify-access settings in the table above.

**Server-wide** (read from whichever provider's scope sets them; a provider that says nothing about a
setting leaves it alone):

| Setting | Scope key | System property | Environment variable | Default |
|---|---|---|---|---|
| SSRF allow-list (comma-separated hosts) | `allowed-internal-hosts` | `lws.authn.allowedInternalHosts` | `LWS_AUTHN_ALLOWED_INTERNAL_HOSTS` | — |
| Outbound fetch timeout (ms) | `http-timeout-millis` | `lws.authn.http.timeoutMillis` | `LWS_AUTHN_HTTP_TIMEOUT_MILLIS` | `5000` |
| Outbound response cap (bytes) | `http-max-response-bytes` | `lws.authn.http.maxResponseBytes` | `LWS_AUTHN_HTTP_MAX_RESPONSE_BYTES` | `262144` |
| Clock skew allowed on `exp`/`nbf`/`<Conditions>` (s) | `clock-skew-seconds` | `lws.authn.clockSkewSeconds` | `LWS_AUTHN_CLOCK_SKEW_SECONDS` | `60` |

Out-of-range values are clamped rather than honoured (timeout 100 ms–60 s, response cap 1 KiB–16 MiB,
skew 0–600 s), and a value that will not parse falls back to the default.

**Per realm.** `enabled` is the one setting realms of the same server sensibly differ on, so it also
honours a realm attribute — `lws.authn.<providerId>.enabled` (for example
`lws.authn.lws-saml.enabled`) set to `true` or `false` overrides the provider-wide flag for that realm
alone. A disabled suite answers `404` on both its endpoints.

---

## Notes & limitations

- **Key/identity hosting.** The OpenID and self-signed-CID `cid/{userId}` endpoints serve
  Keycloak-hosted identifiers; private keys never reach Keycloak (only public JWKs are registered). The
  SAML and `did:key` suites host nothing.
- **SAML trust is out-of-band.** The verifier requires the trusted IdP certificate as input; it
  validates the XML signature, the `<Conditions>` window (±60 s skew by default, `clock-skew-seconds`)
  and the audience, but does not fetch metadata or build a trust chain.
- **`did:key` key types.** Ed25519, P-256, P-384 and P-521 are supported; secp256k1 (which the JDK
  cannot do without BouncyCastle) and RSA are not. No BouncyCastle is used, so this works under both
  default and FIPS Keycloak crypto. Curve parameters come from the JDK rather than being transcribed
  here, so the set is one table row per curve.
- **`frontendUrl`.** Derived identifiers and served documents are built from the realm front-end URL;
  set it (or run behind a stable hostname) so they stay consistent and publicly dereferenceable.
- **Verifier networking & syntaxes.** OpenID/self-signed-CID verification dereferences `sub` (and, for
  OpenID, performs Discovery). Verifiers request Turtle first. Turtle / N-Triples / RDF/XML are parsed
  with Jena RIOT, and **JSON-LD is processed properly** — Jena's JSON-LD 1.1 reader — so a conforming
  controlled identifier document verifies whatever shape it is written in: aliased terms, an
  `@graph` wrapper, referenced rather than embedded verification methods, additional contexts.
  - Contexts are resolved from **copies bundled in the JAR**, never fetched. A JSON-LD processor left
    to itself would request every `@context` URL a credential's document names — an unvetted outbound
    fetch during verification, and a dependency on `w3.org` being reachable for anything to verify at
    all. A document naming a context this provider does not bundle is refused as unverifiable rather
    than guessed at; the older key-walking reader remains as a fallback for the compact shape.
- **Cacheable identity documents.** The `cid/{userId}` endpoints negotiate on `Accept` q-values,
  answer `406` when nothing on offer is acceptable, and carry `Vary: Accept`, `ETag` and
  `Cache-Control` (`cid-cache-seconds`, default 300) so a verifier can cache them — which both suite
  drafts encourage, "to reduce unnecessary network requests and the associated metadata leakage".
- **Verification-method identifiers.** A JWK `kid` is arbitrary text, so the self-signed-CID document
  percent-encodes it into the `<subject>#<kid>` fragment rather than producing an IRI Jena refuses to
  serialize. Every method has an `id`, as CID 1.0 requires: when the `kid` cannot supply the fragment —
  absent, blank, over-long, or not well-formed text — the position stands in as `#key-<n>`. The
  verifier matches a credential's `kid` against a method's fragment both raw and decoded, so documents
  from other implementations still resolve.
- **Audience / token exchange.** Every `/verify` endpoint accepts an `audience` parameter (and the
  OpenID one a `client_id`) so the credential can be bound to the party checking it — and a deployment
  can require one for every request with the `audience` setting, rather than trusting each caller to
  remember the optional parameter; each result reports
  the LWS `client` and the suite's `tokenType`, ready for an RFC 8693 exchange. Restrict credential
  audiences at issuance too (Resource Indicators, RFC 8707).

## Layout

```
src/main/java/com/ebremer/lws/authn/
  config/                                       configuration surface
    Settings                                    scope -> system property -> environment -> default
    ServerSettings                              server-wide tunables (SSRF list, timeouts, skew)
    EndpointSettings                            per-provider settings, incl. the per-realm on/off flag
  http/                                         shared endpoint plumbing
    JsonResponses                               every non-result body, serialized not concatenated
    CidEndpoint                                 the shared cid/{userId} endpoint
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

Every source file carries `SPDX-License-Identifier: Apache-2.0`; the project is Apache-2.0 (see
[`LICENSE`](LICENSE)).
