# TODO — `lws-authn`

Prioritized backlog from a full code review of this repository against the **current W3C Linked Web
Storage drafts** (checked 2 September 2026) and against the normative specifications those drafts
incorporate by reference (CID 1.0, OpenID Connect Core 1.0, RFC 7515, SAML 2.0 Core, RFC 9110).

Every item names the file (and line, where useful) and states what the spec requires versus what the
code does today. Items are ordered so the highest-risk work comes first; within a priority band the
order is roughly "cheapest first".

**State of the tree at review time:** `mvn package` succeeded and `mvn test` was green (21 tests, 0
failures). Nothing below is a build breakage — these are security, conformance, robustness and
hygiene gaps.

> ### P0, P1, P2 and P4 are done
>
> `mvn clean verify` is green: **114 unit tests** (21 before this work started) and **10** in
> `LwsAuthIT` against a real Keycloak 26.7.3 container. The changes worth knowing about
> before reading further:
>
> - **The `…/verify` endpoints are now authenticated by default** (`access=bearer`). This is a
>   breaking change for an existing deployment; `LWS_AUTHN_VERIFY_ACCESS=public` restores the old
>   behaviour. See "Securing the verify endpoints" in `README.md`.
> - **`Authorization` on a verify request now means the caller's credential**, not the credential
>   under test, except in `public` mode. The credential under test goes in the `credential` form field.
> - The verifiers fetch through their **own** HTTP client: redirects disabled, and `SsrfGuard`
>   installed as its DNS resolver so the vetted addresses are the connected ones. `OutboundHttpClientTest`
>   proves both against a real server; `lws.authn.http.mode=session` falls back to Keycloak's client.
> - Verify responses no longer carry upstream status codes, resolved addresses or exception text; they
>   carry a `traceId` and the detail is logged at `DEBUG`.
> - `lws_jwk` values carrying private key material are refused and logged, never published.
> - The SAML verifier now checks `<samlp:Status>`, the IdP certificate's own validity, and the bearer
>   `<SubjectConfirmationData>` (method, `Recipient`, `NotOnOrAfter`).
>
> **Integration test:** `mvn clean verify` passes — 114 unit tests plus 10 in `LwsAuthIT`, which deploys
> the shaded JAR into a real Keycloak 26.7.3 container. It has earned its keep twice: on P4 it caught a
> packaging change that broke Jena's Turtle writer, and on P2 it found that no EC-signed credential
> could be verified in any suite. Neither was visible to a unit test — the first needs the real
> classpath, the second needs Keycloak's crypto providers.
>
> P3-1 (a `401` with no `WWW-Authenticate` when a *credential* is invalid) is now more visible than it
> was: access-control denials send a challenge and credential rejections do not, which is what
> currently distinguishes them. It stays a P3.
>
> ### P1 (all 19 items)
>
> - **Every verify result now names the LWS `client` and the suite's `tokenType`** (core §4.1, §4.3),
>   and fails closed when the client identifier is absent. That retired four dead constants.
> - **OpenID:** `azp` is required; `crit` is rejected; the CID's `id` must equal `sub` on *both* syntax
>   paths (the JSON-LD one used to default a missing `id` to the subject, accepting a document that
>   never claimed to describe it); and `POST …/lws/verify` takes `client_id` and `audience` to enforce
>   OpenID Connect Core §3.1.3.7 steps 3–5, which the suite incorporates by reference.
> - **Self-signed CID:** `iat` and `kid` required; `crit` rejected; the document `id` must equal `sub`
>   on the JSON-LD path too; a method is only usable if it is a `JsonWebKey` the subject **controls**;
>   the `alg` is pinned to the published key and cross-checked against the JWK's own `use`/`alg`; and
>   `audience` binds the credential to this authorization server.
> - **did:key:** `iat` required, `crit` rejected, `audience` honoured; **P-384 and P-521 added**
>   alongside Ed25519 and P-256; and a `did:key` must be **canonically encoded** — the decoded key is
>   re-encoded and must reproduce the identifier, so one key cannot have two identifiers. Curve
>   parameters now come from the JDK instead of hand-transcribed constants.
> - **SAML:** `<Issuer>` is required rather than merely recorded.
>
> ### P4 (all six items)
>
> - **Libraries Keycloak already ships were bundled unrelocated** — including
>   `org.glassfish:jakarta.json` 2.0.1, an *older* copy of the same `jakarta.json.*` packages the server
>   supplies at 2.1.3. Two implementations of one package is a split-package hazard.
> - The fix is two strategies, chosen per library, and getting it wrong fails either way: where
>   Keycloak's copy satisfies Jena it is now `provided`; where **Jena needs a newer version**
>   (`titanium-json-ld` 1.7.0 vs Keycloak's 1.3.3, `commons-collections4` 4.5.0 vs 4.4, `caffeine`
>   3.2.4 vs 3.2.3) it is bundled and **relocated**, as `commons-codec` already was. Those versions are
>   pinned explicitly: Maven breaks the tie by declaration order and would otherwise have relocated
>   Keycloak's older copy — a four-minor downgrade of the library Jena parses JSON-LD with.
> - `maven-enforcer-plugin` (duplicate classes over the bundled scopes, duplicate POM versions, Java and
>   Maven floors) and a CycloneDX SBOM at `target/bom.json`. The shade `artifactSet` excludes are the
>   guard that actually holds for what must never be bundled. Note `banDuplicateClasses` cannot cover
>   `provided`: Keycloak's own tree duplicates classes across its modules.
> - **`maven-jar-plugin` now sets `forceCreation`.** Shade replaces `target/lws-authn-0.1.0.jar` with
>   its own output, so on a second `package` without `clean` the jar plugin saw a file newer than
>   `target/classes`, skipped rebuilding, and shade re-shaded its own previous output. That was latent
>   before; adding a licence entry turned it into a hard `duplicate entry` failure, which is how it
>   surfaced.
> - **P4-1 turned out to be a misreading** — see the item below. `commons-compress` is Jena's, not a
>   Testcontainers leak, and removing it broke Turtle serialisation.
> - LICENSE/NOTICE are merged rather than one surviving arbitrarily, `META-INF/maven/**` and
>   multi-release `module-info` no longer collide, and the JAR now actually carries a licence — the
>   Apache transformer drops every `META-INF/LICENSE` it sees, ours included, so it is re-added as
>   `META-INF/LICENSE-lws-authn.txt`.
> - Keycloak 26.7.0 → **26.7.3**, Jena 6.1.0 → **6.2.0**, JUnit 5.11.4 → **5.14.4** (staying on the 5.x
>   line; JUnit 6 is a separate migration), testcontainers-keycloak → **4.3.1**, bcpkix → **1.85**.
>   Version references in the docs, scripts and the IT container image were updated to match.
>
> ### P2 (all nine items)
>
> - **JSON-LD is now processed, not pattern-matched.** The verifiers walked the exact key names this
>   project emits, so a conforming document from any other implementation — aliased terms, an
>   `@graph`, a referenced verification method — simply found nothing. Jena's JSON-LD 1.1 reader does
>   the work now, with contexts served from the JAR so verification makes no outbound context fetch and
>   does not depend on `w3.org` being up. The old reader stays as a fallback for unbundled contexts.
> - The `cid/{userId}` endpoints honour `Accept` q-values (they were doing a substring test in a fixed
>   order, so a client asking for JSON-LD at `q=1.0` got Turtle at `q=0.1`), answer `406` instead of
>   serving something unasked for, and carry `Vary`, `ETag` and `Cache-Control`.
> - The WebID user attribute must be an absolute `http(s)` URL or it is refused in favour of the hosted
>   WebID, since a `sub` nobody can dereference produces a token that looks right and is rejected
>   everywhere.
> - 60 seconds of clock skew on `exp`/`nbf`, shared with the SAML verifier so one deployment does not
>   apply two tolerances; the OpenID CID's service entry is named rather than a blank node; and the
>   JOSE `typ` header is rejected when present and wrong (absent is still fine — issuers omit it).
> - Replay detection exists but is **off by default**, which is the point of the item rather than a
>   shortcut: a verify endpoint is asked about the same live credential on every request that carries
>   it, so refusing a second look would break the primary use. See `ReplayCache`.
>
> **Two bugs the new integration test found, both older than P2.** `LwsAuthIT` now drives a JSON-LD
> document served by a third party, which is the first time the self-signed-CID *verify* path had ever
> run inside Keycloak:
>
> - **No EC-signed credential could be verified, in any suite.** The verifiers passed the JCA key
>   algorithm (`ECDSA`) where Keycloak wants its own `KeyType` (`EC`), so its signature provider
>   refused the key. ES256 is the algorithm every LWS suite example uses. Only RSA worked, which is why
>   the OpenID path passed and nothing else was exercised.
> - **A bodiless response became a 500.** Keycloak's `DefaultSecurityHeadersProvider` rejects any
>   response with no content type, so the new `406` — and the pre-existing `404` for an unknown user —
>   arrived as `unknown_error`.
>
> **Behaviour that got stricter.** Credentials that used to verify and now will not: an ID Token with
> no `azp`; a self-issued JWT with no `iat` or no `kid`; a controlled identifier document whose `id`
> is missing or differs from the subject, or whose verification methods lack `type`/`controller`; a
> non-canonically-encoded `did:key`; a SAML assertion with no `<Issuer>`. Each is a MUST in the
> drafts, but any of them may be a real credential in the wild, so check your issuers before rolling
> this out.

---

## Specification baseline

| Document | Latest published version | Editor's Draft |
|---|---|---|
| Linked Web Storage Protocol 1.0 (core) | **W3C Working Draft 21 August 2026** — `TR/2026/WD-lws10-core-20260821/` | `w3c.github.io/lws-protocol/lws10-core/` |
| LWS 1.0 Authn Suite: Self-signed Identity (Controlled Identifiers) | **W3C Working Draft 21 August 2026** — `TR/2026/WD-lws10-authn-ssi-cid-20260821/` | `w3c.github.io/lws-protocol/lws10-authn-ssi-cid/` |
| LWS 1.0 Authn Suite: OpenID Connect | W3C Working Draft 3 August 2026 — `TR/2026/WD-lws10-authn-openid-20260803/` | `w3c.github.io/lws-protocol/lws10-authn-openid/` |
| LWS 1.0 Authn Suite: SAML 2.0 | W3C Working Draft 3 August 2026 — `TR/2026/WD-lws10-authn-saml-20260803/` | `w3c.github.io/lws-protocol/lws10-authn-saml/` |
| LWS 1.0 Authn Suite: Self-signed Identity using `did:key` | W3C Working Draft 3 August 2026 — `TR/2026/WD-lws10-authn-ssi-did-key-20260803/` | `w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/` |
| Linked Web Storage Vocabulary | Group Note draft, 2026-08-21 | `w3c.github.io/lws-protocol/lws10-vocab/` |
| Controlled Identifiers (CID) 1.0 | **W3C Recommendation, 15 May 2025** | — |

Facts from those documents that shape the items below:

* **Core §4.1** — a credential MUST carry *subject* (URI, REQUIRED), *issuer* (URI, REQUIRED),
  *client* (REQUIRED, SHOULD be a URI), and a RECOMMENDED audience restriction naming the
  authorization server. **§4.2** — a credential MUST be signed; asymmetric signatures RECOMMENDED.
  **§4.3** — each suite MUST be associated with a token type URI.
* **`lws:OpenIdProvider`** is confirmed by the LWS Vocabulary (2026-08-21) at
  `https://www.w3.org/ns/lws#OpenIdProvider` — the value hard-coded in `LWSConstants` is correct.
* The `https://www.w3.org/ns/cid/v1` context maps `authentication` →
  `https://w3id.org/security#authenticationMethod`; `verificationMethod`, `controller` and
  `publicKeyJwk` (`@json`, scoped under the `JsonWebKey` type) → `https://w3id.org/security#…`; and
  `service` / `serviceEndpoint` → `https://www.w3.org/ns/did#…`. **Every IRI in `LWSConstants` and
  `SsiCidConstants` matches the context — nothing to change there.**

---

## P0 — Security (fix before exposing `/verify` on the public internet)

- [x] **P0-1 · The self-signed-CID endpoint publishes whatever is in `lws_jwk`, private keys included.**
  `ssicid/resource/SsiCidResourceProvider.java:82-94` reads every `lws_jwk` attribute value, and
  `ssicid/cid/SelfSignedControlledIdentifierDocument.java:71` / `:102` embeds it verbatim. CID 1.0
  states the `publicKeyJwk` map *"MUST NOT include any members of the private information class, such
  as `d`"*. One mis-pasted full JWK publishes the agent's private key at a world-readable URL.
  **Do:** whitelist public JWK members (`kty, kid, alg, use, key_ops, crv, x, y, n, e, x5c, x5t,
  x5t#S256`); drop the attribute value and log a warning if it contains any of
  `d, p, q, dp, dq, qi, k, oth`. Add a regression test.

- [x] **P0-2 · The demo and walkthrough tell operators to make `lws_jwk` user-writable.**
  `scripts/ssi-cid-demo.sh:59` and `docs/walkthrough-ssi-cid.md:53` set
  `unmanagedAttributePolicy = "ENABLED"`. In Keycloak 26 that policy
  (`UPConfig.UnmanagedAttributePolicy` = `ENABLED | ADMIN_VIEW | ADMIN_EDIT`) lets **end users**
  manage the attribute. A user can therefore register an arbitrary public key against their own
  hosted controlled identifier and mint credentials for that identity; and if `LWSSubMapper`'s WebID
  attribute is likewise unmanaged, a user can set their own `sub` and impersonate any WebID.
  **Do:** change both to `ADMIN_EDIT`; state the requirement in `README.md` and `INSTALL.md`; make
  `LWSSubMapper`'s help text say the WebID attribute must never be user-writable.

- [x] **P0-3 · `/verify` endpoints are unauthenticated and drive outbound HTTP from attacker-supplied URLs.**
  `openid/resource/LWSResourceProvider.java:102-127` and
  `ssicid/resource/SsiCidResourceProvider.java:110-135` accept an anonymous POST that triggers up to
  three outbound fetches (`sub`, OIDC discovery, JWKS) at 5 s timeouts each. The spec's cold-trust
  algorithm requires fetching *before* the signature is known good, so the ordering cannot be fixed —
  the exposure has to be. Result: request amplification, a network-probe oracle, and a cheap DoS.
  **Do:** gate the endpoints behind a credential (bearer token or configured shared secret) by
  default; add per-caller rate limiting and a short negative cache; make them opt-in per realm through
  provider configuration (see P3-6).

- [x] **P0-4 · Verifier responses leak internal network detail to anonymous callers.**
  `net/SsrfGuard.java:78` embeds the *resolved internal IP* in its exception message, and
  `openid/verify/LWSCredentialVerifier.java:168,201,332` (plus the SSI-CID and did:key equivalents)
  copy `e.getMessage()` straight into the JSON body; `:189` also echoes the upstream HTTP status.
  **Do:** return coarse reason codes to the client (`subject_not_dereferenceable`,
  `issuer_not_discoverable`, `key_not_found`); log the detail server-side with a correlation id and
  return only that id.

- [x] **P0-5 · DNS-rebinding TOCTOU in `SsrfGuard`.**
  `net/SsrfGuard.java:70-81` resolves the host and checks the addresses; Apache HttpClient then
  resolves the name *again* at connect time. A hostile `sub` host with a 0-TTL record alternating
  between a public and an internal address defeats the guard.
  **Do:** resolve once, verify every returned address, and connect to a pinned address — which needs a
  dedicated `HttpClient` with a custom `DnsResolver` / route planner, since Keycloak's `SimpleHttp`
  does not expose this. Keep the existing pre-check as defence in depth.

- [x] **P0-6 · Redirect handling is safe only because of a Keycloak default that can be turned off.**
  Verified in `keycloak-services` 26.7.x: `DefaultHttpClientFactory` calls `disableRedirectHandling()`
  and documents `allow-redirects` as *"Default: false"*. But a deployment that sets
  `spi-connections-http-client-default-allow-redirects=true` silently makes every `SsrfGuard` check
  bypassable via a 302 to an internal address, with no signal to the operator.
  **Do:** stop depending on server-wide config — use a private client with redirects disabled, or
  re-run `SsrfGuard` on each hop. Correct the wording in `README.md` and `INSTALL.md` §9c (see P6-2).

- [x] **P0-7 · The SAML verifier accepts an expired or not-yet-valid IdP certificate.**
  `saml/resource/SamlResourceProvider.java:73` decodes the PEM;
  `saml/verify/SamlCredentialVerifier.java:65` uses only `idpCertificate.getPublicKey()`.
  `X509Certificate.checkValidity()` is never called.
  **Do:** call it, expose the outcome as a `certificateValid` check, and allow an explicit
  `allowExpiredCertificate` opt-out for offline replay analysis.

- [x] **P0-8 · The SAML verifier ignores `<samlp:Status>`.**
  `saml/verify/SamlCredentialVerifier.java:53-154` never inspects the Status element, so a Response
  carrying `…:status:Requester` or `…:status:AuthnFailed` still validates as long as it embeds a
  signed assertion.
  **Do:** when the credential is a `<samlp:Response>`, require
  `Status/StatusCode/@Value == urn:oasis:names:tc:SAML:2.0:status:Success` (SAML 2.0 Core §3.2.2).

- [x] **P0-9 · Bearer `SubjectConfirmationData` constraints are not enforced.**
  `saml/verify/SamlCredentialVerifier.java:103-106` reads `Recipient` and stops. `@NotOnOrAfter`,
  `@NotBefore` and `SubjectConfirmation/@Method` are ignored, so the bearer-subject window from the
  Web Browser SSO profile is never applied — only `<Conditions>` is.
  **Do:** require `Method == urn:oasis:names:tc:SAML:2.0:cm:bearer`, enforce the
  `SubjectConfirmationData` window with the same skew as `<Conditions>`, and require `Recipient`
  (see P1-M2).

---

## P1 — Specification conformance: MUST-level gaps

### Cross-cutting (LWS core §4.1 / §4.3)

- [x] **P1-K1 · "client" is REQUIRED by core §4.1, but only two of four suites enforce it.**
  SSI-CID and did:key check `client_id`; the OpenID verifier never reads `azp` (P1-O1) and the SAML
  verifier treats `Recipient` as optional (P1-M2).
  **Do:** make every verification result carry a `client` field, and fail closed when it is absent.

- [x] **P1-K2 · The token type URIs required by core §4.3 are declared and never used.**
  `LWSConstants.TOKEN_TYPE_ID_TOKEN`, `SsiCidConstants.TOKEN_TYPE_JWT`,
  `DidKeyConstants.TOKEN_TYPE_JWT` and `SamlConstants.TOKEN_TYPE_SAML2` have **zero** references in
  `src/` — as do `SamlConstants.SAML_PROTOCOL_NS`, `SamlConstants.NAMEID_FORMAT_PERSISTENT` and
  `SsiCidConstants.SEC_VERIFICATION_METHOD`.
  **Do:** emit `token_type` (and `client`) in each `/verify` response so a caller can drive an RFC 8693
  exchange directly — or delete the dead constants. Don't leave them as decoration.

### OpenID Connect suite

- [x] **P1-O1 · `azp` is a MUST, and is neither produced-as-a-URI nor validated.**
  Spec: *"The ID Token MUST use the `azp` (authorized party) claim for the LWS client identifier."*
  `openid/verify/LWSCredentialVerifier.java` never reads `azp`. On the issuing side Keycloak's `azp`
  is the raw OIDC client id (`lws-app` in `examples/lws-demo-realm.json`), which is not a URI, while
  core §4.1 says the client identifier SHOULD be one.
  **Do:** require a non-blank `azp` in the verifier and surface it; document (or add a mapper for)
  making the client identifier a URI.

- [x] **P1-O2 · OpenID Connect Core §3.1.3.7 steps 3–5 are not implemented.**
  The suite says *"The JWT MUST be validated as described by OpenID Connect Core Section 3.1.3.7."*
  Steps 3–5 of that section require: `aud` contains the client's `client_id`; if `aud` has multiple
  values then `azp` MUST be present; and if `azp` is present it MUST equal the `client_id`.
  `openid/verify/LWSCredentialVerifier.java:162-165` explicitly opts out of `aud` altogether.
  **Do:** accept optional `client_id` and `audience` form parameters on `POST …/lws/verify` and enforce
  steps 3–5 when they are supplied; enforce the `azp`-presence rule unconditionally. Keep the
  "audience confinement is the RP's job" position, but make the check *available*.

- [x] **P1-O3 · A controlled identifier document with no `id` is accepted.**
  Spec: the dereferenced resource *"MUST be formatted as a valid controlled identifier document with an
  `id` value equal to the subject identifier"*, and CID 1.0 requires an `id` in the topmost map.
  `openid/verify/LWSCredentialVerifier.java:220` falls back to `sub` when neither `id` nor `@id` is
  present, so a document omitting `id` passes. The Turtle / N-Triples path enforces the match
  implicitly by binding `?sub`, so the two paths disagree.
  **Do:** require an explicit `id`/`@id`, compare it to `sub`, and record a `subjectIdMatches` check on
  both paths.

- [x] **P1-O4 · The `crit` JOSE header is never inspected.**
  RFC 7515 §5.2 — cited normatively by the SSI suites and reachable from OIDC Core — requires a verifier
  to reject a JWS whose header carries critical parameters it does not understand. None of the three
  JWT verifiers looks at `crit`.
  **Do:** reject any credential with a non-empty `crit` header, via a shared helper (covers O4, C-*, D3).

### Self-signed CID suite *(the 21 August 2026 draft)*

- [x] **P1-C1 · `iat` is a MUST and is not checked.**
  Spec: *"The JWT MUST include an `iat` (issued at) claim."*
  `ssicid/verify/SelfSignedCidVerifier.java` validates `exp` and `aud` but never `iat`.
  **Do:** require `iat`; add an `issuedAtPresent` check; optionally reject an `iat` in the future beyond
  the skew allowance, and offer a configurable maximum credential age.

- [x] **P1-C2 · `aud` MUST include the target authorization server; only presence is checked.**
  `ssicid/verify/SelfSignedCidVerifier.java:141-147` asserts `aud` is non-empty and stops.
  **Do:** add an `audience` form parameter (the SAML endpoint already has one — mirror it) and require
  containment; keep presence-only as an explicitly reported fallback mode.

- [x] **P1-C3 · Key selection falls back when the header has no `kid`.**
  Spec: *"The verifier MUST use the `kid` (key id) value from the signed JWT header to identify a
  verification method."* `ssicid/verify/SelfSignedCidVerifier.java:234-247` returns the single key when
  `kid` is absent.
  **Do:** reject credentials with no `kid`.

- [x] **P1-C4 · The JSON-LD path never checks that the document's `id` equals `sub`.**
  `ssicid/verify/SelfSignedCidVerifier.java:187-193` collects `authentication` / `verificationMethod`
  entries from the top-level object without ever reading `id`. The RDF path enforces the relationship by
  binding `?sub`; the two paths again disagree.
  **Do:** read `id`, compare it to `sub`, and collect only methods reachable from it.

- [x] **P1-C5 · The verification method's `controller` and `type` are never checked.**
  CID 1.0 makes `id`, `type` and `controller` REQUIRED on a verification method. Neither the JSON-LD
  collector (`:195-205`) nor the SPARQL collector (`:211-231`) looks at them.
  **Do:** accept a key only when `type` is `JsonWebKey` and `controller` equals `sub`.

- [x] **P1-C6 · The served CID omits the REQUIRED verification-method `id` when the JWK has no `kid`.**
  `ssicid/cid/SelfSignedControlledIdentifierDocument.java:65-68` adds `id` only when a `kid` is present,
  and `:99` falls back to a blank node in the RDF serialization. CID 1.0: a verification method's `id`
  MUST be a string conforming to URL syntax.
  **Do:** require a `kid` on registered JWKs (rejecting the attribute value otherwise, consistent with
  P1-C3) or synthesize `#key-<n>`; URL-encode the fragment (see P3-3).

- [x] **P1-C7 · No algorithm/key pinning in the SSI-CID verifier.**
  The OpenID verifier has `algMatchesKey` (`openid/verify/LWSCredentialVerifier.java:343-358`) and the
  did:key verifier pins `alg` to the decoded key type, but
  `ssicid/verify/SelfSignedCidVerifier.java:106-120` passes the header `alg` straight to
  `session.getProvider(SignatureProvider.class, alg)`. An `HS256` header against an RSA/EC
  `publicKeyJwk` fails only incidentally, deep inside Keycloak.
  **Do:** hoist `algMatchesKey` into a shared helper and apply it here; also require the JWK's own
  `kty` / `crv` / `alg` / `use` to be consistent with the header algorithm.

### Self-signed `did:key` suite

- [x] **P1-D1 · `iat` is a MUST and is not checked.** Same gap as P1-C1, in
  `ssididkey/verify/SelfSignedDidKeyVerifier.java:100-117`.

- [x] **P1-D2 · `aud` MUST include the target authorization server; only presence is checked.**
  `ssididkey/verify/SelfSignedDidKeyVerifier.java:111-117`. Same fix as P1-C2.

- [x] **P1-D3 · `crit` header not inspected.** Same as P1-O4.

- [x] **P1-D4 · Only two `did:key` multicodecs are supported, and the limit is not stated as a
  conformance claim.** `ssididkey/DidKey.java:35-36,64-70` handles Ed25519 (`0xed01`) and P-256
  (`0x1200`). The did:key registry also defines P-384 (`0x1201`, ES384), P-521 (`0x1202`, ES512),
  secp256k1 (`0xe701`, ES256K) and RSA (`0x1205`); the LWS draft mandates no particular set, so a
  conforming peer may present any of them and this verifier rejects it.
  **Do:** add P-384 and P-521 (pure JDK — the same compressed-point decompression with the right curve
  parameters); decide explicitly on secp256k1 / RSA; publish the supported set as a conformance
  statement in `README.md` and `COMPLIANCE.md`.

- [x] **P1-D5 · Non-canonical `did:key` encodings are accepted.**
  `ssididkey/DidKey.java:51-71` decodes whatever base58btc parses; it never re-encodes and compares, so
  distinct identifier strings can map to the same key.
  **Do:** re-encode the decoded key and require an exact, byte-for-byte match with the input identifier.

### SAML 2.0 suite

- [x] **P1-M1 · `saml:Issuer` is a MUST and is not required.**
  Spec: *"The SAML token MUST use the `saml:Issuer` assertion for the LWS issuer identifier."*
  `saml/verify/SamlCredentialVerifier.java:100-101` records it and tolerates `null`.
  **Do:** require a non-empty `<Issuer>` inside the cryptographically covered assertion.

- [x] **P1-M2 · `Recipient` is a MUST (it carries the LWS client identifier) and is optional in code.**
  *Done with P0-9 — the verifier now requires it. The optional `expectedRecipient` parameter is still
  outstanding.*
  Spec: *"The SAML token MUST use the `Recipient` parameter within a `saml:SubjectConfirmationData`
  assertion for the LWS client identifier."* Combined with core §4.1 (client REQUIRED),
  `saml/verify/SamlCredentialVerifier.java:103-106` should not treat it as best-effort.
  **Do:** require `Recipient`; add an optional `expectedRecipient` parameter alongside `audience`.

---

## P2 — Specification conformance: SHOULD-level, interop and privacy

- [x] **P2-1 · JSON-LD is pattern-matched, not processed.**
  `openid/verify/LWSCredentialVerifier.java:214-239` and
  `ssicid/verify/SelfSignedCidVerifier.java:187-205` understand only the compact shape this project
  itself emits. A conforming CID using `@graph`, term aliases, or an extra context will not verify — an
  interop failure against other LWS implementations.
  The comment at `LWSCredentialVerifier.java:207-213` justifies this by a Titanium version conflict, but
  that no longer describes the build: `com.apicatalog:titanium-json-ld:1.3.3` **is already shaded into
  the provider JAR** (it resolves at `compile` scope through Keycloak's own dependency tree).
  **Do:** relocate `com.apicatalog` and `jakarta.json` the way `commons-codec` already is; read JSON-LD
  through Jena RIOT with a **bundled local copy** of `https://www.w3.org/ns/cid/v1` (never fetched at
  verify time); keep the compact reader as a fallback. Then fix the stale comment.

- [x] **P2-2 · Content negotiation on the CID endpoints ignores q-values.**
  `openid/resource/LWSResourceProvider.java:130-145` and
  `ssicid/resource/SsiCidResourceProvider.java:137-152` do a plain substring match, so
  `Accept: application/ld+json;q=1.0, text/turtle;q=0.1` returns Turtle. An unsatisfiable `Accept`
  silently yields JSON-LD instead of 406.
  **Do:** use JAX-RS `Request.selectVariant(...)` (or parse q-values) and return 406 when nothing matches.

- [x] **P2-3 · No `Vary: Accept` on the content-negotiated CID responses.** A shared cache will serve one
  client's Turtle to another that asked for JSON-LD. Add the header.

- [x] **P2-4 · No `Cache-Control` / `ETag` on CID responses.** Both suite drafts' privacy sections
  encourage verifiers to *"cache controlled identifier documents to reduce … metadata leakage"*, but the
  served documents give a cache nothing to work with.
  **Do:** emit a configurable `Cache-Control: public, max-age=…` plus a strong `ETag`, and honour
  `If-None-Match`.

- [x] **P2-5 · The WebID user attribute is trimmed but never validated as an absolute URI.**
  `openid/LWSSubMapper.java:137-160`. Core §4.1 requires the subject to be a URI; a value like
  `alice@example.org` becomes a `sub` no verifier can dereference.
  **Do:** validate with `java.net.URI` (absolute, `http`/`https`); on failure log a warning and fall back
  to the hosted WebID rather than issuing an unusable credential.

- [x] **P2-6 · Give the OpenID CID's service map an `id`.**
  `openid/cid/ControlledIdentifierDocument.java:61` uses a blank node. CID 1.0 makes service `id`
  OPTIONAL, so this is **not** a violation — but naming it (`<webid>#openid-provider`) makes the document
  addressable and matches what most CID consumers expect.

- [x] **P2-7 · No clock-skew allowance on `exp`.** Verified: `JsonWebToken.isActive()` calls
  `isActive(10)`, which applies 10 s of leeway to `nbf` only; `exp` is compared exactly. All three JWT
  suites say *"Implementers MAY provide for some small leeway to account for clock skew."*
  **Do:** add a small configurable skew — the SAML verifier already uses ±60 s
  (`saml/verify/SamlCredentialVerifier.java:44`); make the two consistent.

- [x] **P2-8 · No replay protection.** No suite mandates it, but nothing prevents an intercepted
  credential being replayed at every verifier until `exp`.
  **Do:** consider a bounded, TTL'd per-realm `jti` cache for the two self-issued suites, reported as a
  `jtiSeen` check.

- [x] **P2-9 · The `typ` header is not checked** (RFC 8725 §3.11). Low risk here because each endpoint is
  suite-specific, but recording it in the result costs nothing.

---

## P3 — Correctness and robustness

- [ ] **P3-1 · `/verify` returns 401 with no `WWW-Authenticate` header.**
  `openid/resource/LWSResourceProvider.java:122`, `ssicid/resource/SsiCidResourceProvider.java:130`,
  `ssididkey/resource/DidKeyResourceProvider.java` and `saml/resource/SamlResourceProvider.java:84` all
  return `Response.Status.UNAUTHORIZED`. RFC 9110 §15.5.2: *"The server generating a 401 response MUST
  send a `WWW-Authenticate` header field."* The status is also semantically wrong — the *request* was
  authorized; the *submitted credential* was not valid.
  **Do:** return `200 OK` with `{"valid": false, …}`, and reserve 401 (with a proper challenge) for an
  unauthenticated caller once P0-3 lands.

- [ ] **P3-2 · JSON built by string concatenation.**
  `saml/resource/SamlResourceProvider.java:91-95` interpolates a message into a JSON literal; the other
  three providers do the same for their "missing credential" body. Every current caller passes a
  constant, so nothing is broken today — but it is one edit from emitting malformed JSON.
  **Do:** serialize with `JsonSerialization` everywhere.

- [ ] **P3-3 · An unencoded `kid` can produce an invalid IRI and a 500 from the CID endpoint.**
  `ssicid/cid/SelfSignedControlledIdentifierDocument.java:66` and `:99` build `id + "#" + kid` with no
  escaping; a `kid` containing a space, `#` or `/` yields an IRI Jena rejects when serializing Turtle.
  **Do:** URL-encode the fragment and reject `kid`s that cannot be encoded (pairs with P1-C6).

- [ ] **P3-4 · SPARQL predicates hardcoded as strings instead of the constants that exist for them.**
  `ssicid/verify/SelfSignedCidVerifier.java:213-216` writes `sec:authenticationMethod` /
  `sec:verificationMethod` into the query text while `SsiCidConstants.SEC_AUTHENTICATION` and
  `SEC_VERIFICATION_METHOD` sit unused (the latter has zero references anywhere).
  **Do:** bind them as IRI parameters, as the subject already is.

- [ ] **P3-5 · Unknown content types are parsed as Turtle.**
  `rdf/RdfParsing.java:51-62` defaults to `Lang.TURTLE` for any unrecognised `Content-Type`; combined
  with the `{`-sniff in `isJsonLd:36-48`, an HTML error page reaches the Turtle parser. It fails closed,
  but the reported error is misleading.
  **Do:** reject unrecognised content types explicitly, with a clear message.

- [ ] **P3-6 · The SPI provides no configuration surface.**
  `init(Config.Scope)` is empty in all four factories (`openid/resource/LWSResourceProviderFactory.java:28`
  and the SSI-CID / SAML / did:key equivalents), and `net/SsrfGuard.java:122-138` reads its allow-list
  only from a JVM system property or environment variable. There is no supported way to set timeouts,
  clock skew, expected audiences or cache lifetimes, or to disable an endpoint per realm.
  **Do:** wire real `spi-realm-restapi-extension-*` configuration and route the allow-list through it,
  keeping the environment variable as a fallback.

- [ ] **P3-7 · The CID endpoints are unauthenticated and uncached.**
  `openid/resource/LWSResourceProvider.java:70-91` / `ssicid/resource/SsiCidResourceProvider.java:71-104`
  serve any `{userId}` and answer 404 for unknown ones. That is inherent to hosting dereferenceable
  WebIDs, but it deserves an explicit decision: a uniform response shape, plus rate limiting to bound
  scraping.

---

## P4 — Packaging and build

- [x] **P4-1 · ~~A test-scoped dependency leaks a compile-scope artifact into the production JAR.~~
  This finding was wrong.** The original reading — `org.testcontainers:testcontainers` (test) pulling
  `org.apache.commons:commons-compress` in at `compile` scope — came from `mvn dependency:tree`, which
  prints a resolved node **once, under whichever path won**. commons-compress showed under the
  Testcontainers branch, but `jena-base` declares it too, and that is why it was at compile scope.
  It is a genuine Jena runtime dependency: `org.apache.jena.atlas.io.IndentedWriter` touches
  `BZip2CompressorInputStream` in a static initialiser, so without it on the classpath Jena cannot
  write **Turtle**, let alone anything compressed.
  Acting on the wrong reading — pinning it to `test` — broke the CID endpoint with
  `NoClassDefFoundError`, which `LwsAuthIT` caught. It is now declared explicitly at compile scope with
  a comment saying why, so the next reader does not re-derive the same mistake.
  **Lesson for the rest of this file:** `dependency:tree` shows one path per artifact. Use
  `dependency:tree -Dincludes=<ga>` or read the dependency's own POM before concluding that something
  is only reachable through a test dependency.

- [x] **P4-2 · Libraries Keycloak already ships are bundled unrelocated.**
  The shaded JAR currently contains, under their own package names:
  `com.apicatalog:titanium-json-ld:1.3.3`, `com.github.ben-manes.caffeine:3.2.3`,
  `org.apache.commons:commons-collections4:4.4`, `org.jspecify:jspecify:1.0.0`,
  `org.slf4j:slf4j-api:2.0.17`, and — most concerning — **`org.glassfish:jakarta.json:2.0.1`**, an
  *older* implementation of the same `jakarta.json.*` packages Keycloak provides
  (`jakarta.json-api:2.1.3` + `parsson:1.1.7`).
  **Do:** mark the ones Keycloak provides as `provided`, and relocate anything that must stay, exactly
  as `commons-codec` already is in `pom.xml`'s `<relocations>`.

- [x] **P4-3 · Shade resource collisions, one of them a licence obligation.**
  The build warns on overlapping `META-INF/LICENSE`, `META-INF/LICENSE.txt`, `META-INF/MANIFEST.MF` and
  `META-INF/versions/9/module-info`. Only one `LICENSE`/`NOTICE` survives — for a fat JAR of
  Apache-licensed code that is an Apache-2.0 §4(d) obligation, not just noise.
  **Do:** add `ApacheLicenseResourceTransformer` and `ApacheNoticeResourceTransformer`, and exclude
  `META-INF/versions/*/module-info.class` alongside the existing `module-info.class` filter.

- [x] **P4-4 · Dependency updates.** `keycloak.version` 26.7.0 → **26.7.3**; `jena.version` 6.1.0 →
  **6.2.0** (both confirmed latest on Maven Central). Also review `junit-jupiter` 5.11.4,
  `testcontainers-keycloak` 4.2.1 and `bcpkix-jdk18on` 1.84. Re-run the container IT after each bump, and
  update the version strings in `README.md`, `INSTALL.md` and the four walkthroughs in the same commit.

- [x] **P4-5 · No build-time guards.** Add `maven-enforcer-plugin` (dependency convergence, banned
  duplicate classes, required Java version), `cyclonedx-maven-plugin` for an SBOM, and a
  `dependency:analyze` check — so P4-1 and P4-2 fail the build next time instead of needing a review.

- [x] **P4-6 · `pom.xml`'s `<description>` still describes a single-suite project** ("implementing the LWS
  1.0 OpenID Connect Authentication Suite"). It implements four.

---

## P5 — Tests and CI

- [ ] **P5-1 · The verifiers' *network* half is only ever exercised on the happy path.**
  *(Rewritten. The original item asked for a `com.sun.net.httpserver.HttpServer` stub so both verifiers
  could be driven in `mvn test` without Docker. That premise no longer holds — see "why not a unit-level
  stub" below — but the coverage gap it pointed at is real and has moved.)*

  What is covered now: `LWSCredentialVerifierTest` (6) and `SelfSignedCidVerifierTest` (10) between them
  cover every claim- and document-level rule that is decided *before* anything is dereferenced, plus the
  static collectors. `LwsAuthIT` (10) drives both verifiers end to end inside a real Keycloak, including
  a third-party JSON-LD document served over the Testcontainers host bridge.

  What is not: everything between the outbound fetch and the signature, in its failure modes. Nothing
  exercises OpenID Connect Discovery returning a mismatched `issuer`, a configuration with no
  `jwks_uri`, a JWKS with no key matching the token's `kid`, an `HS256` token against an RSA discovery
  key (the algorithm-confusion case `algMatchesKey` exists for), a CID that dereferences but declares no
  `OpenIdProvider` service, or OpenID Connect Core §3.1.3.7 steps 3–5 rejecting a token minted for a
  different relying party. On the self-signed side: a `controller` that is not the subject, a
  `publicKeyJwk` published `use: enc`, an `alg` inconsistent with the published key. Each of these is a
  branch that returns "invalid" — the direction where a bug is silent, because a verifier that wrongly
  rejects gets reported and a verifier that wrongly *accepts* does not.

  **Why not a unit-level stub, as originally written.** `verify()` needs a `KeycloakSession`: it resolves
  `SignatureProvider` from it and fetches through it. Driving the full path off-container means mocking
  a large SPI interface, and what comes back is Keycloak's crypto only by imitation. Both bugs the
  integration test has caught — Jena's Turtle writer losing `commons-compress`, and no EC-signed
  credential verifying in any suite — were invisible to unit tests *by construction*: one needed the
  real shaded classpath, the other needed Keycloak's real signature providers. A stub that mocks the
  session would have passed both. `OutboundHttpClientTest` already shows where an off-container HTTP
  stub does pay: for `OutboundHttp` itself, which takes no session.

  **Do:** extend the host-side server already running in `LwsAuthIT` (`startCidServer`) to serve
  deliberately broken documents and discovery responses, and add the negative cases there. The container
  start is the ~28 s; each additional case costs a fraction of a second, so this is close to free in
  wall-clock and runs against the real classpath and the real crypto. Fold P5-2's list into the same
  pass rather than duplicating it.

- [ ] **P5-2 · Add a negative test for every P0/P1/P2 rule.** Partly done: `alg: none`, missing `iat`,
  missing `azp`, missing `kid`, non-empty `crit`, CID `id ≠ sub`, wrong `controller`, non-canonical
  `did:key`, expired IdP certificate, `StatusCode != Success`, missing `Recipient`, missing `<Issuer>`,
  a `publicKeyJwk` containing `d`, and a non-matching `aud` all have tests now.
  Still missing, and all of them on the network half: HS256 confusion against an RSA key, `use: enc` on
  the selected verification method, discovery `issuer` mismatch, absent `jwks_uri`, no JWK matching the
  `kid`, and §3.1.3.7 steps 3–5. **Do these in the P5-1 pass** — they need the same fixture, and the
  point of both items is the same: the "invalid" branches are where a wrong answer goes unnoticed.

- [ ] **P5-3 · `LwsAuthIT` pins host port 8080** (`src/test/.../LwsAuthIT.java:71`) because the OpenID
  verifier dereferences its own issuer from inside the container. The suite therefore fails whenever
  anything else holds the port, and cannot run in parallel.
  **Do:** document the constraint prominently, or use a random port plus a container-visible hostname
  alias so the issuer URL resolves identically on both sides.

- [ ] **P5-4 · `LwsAuthIT` never asserts a rejection.** Every assertion is "valid: true". Add at least one
  negative case per suite, so a verifier that degrades to "accept everything" fails CI.

- [ ] **P5-5 · CI hardening.** `.github/workflows/ci.yml` has no `permissions:` block, pins actions by tag
  rather than commit SHA, and runs no dependency/vulnerability scan, SBOM upload or CodeQL. It also
  builds only on JDK 21 while development here happens on JDK 25 — add a second job that builds on 25 and
  asserts the class-file version is still 21.

---

## P6 — Documentation

- [ ] **P6-1 · `COMPLIANCE.md` is stale.** It is dated 2026-07-09 and repeatedly calls the suites
  *"unofficial proposals"*. They are now W3C Working Drafts (see the matrix above), and `lws10-core` is a
  Working Draft of 21 August 2026.
  **Do:** rewrite the front matter against the matrix, and restate the "Gaps / softness" tables in terms
  of the item IDs in this file so the two documents stay in sync.

- [ ] **P6-2 · `README.md`'s SSRF section overstates the residual risk on redirects.** It lists "HTTP
  redirects to an internal target" as an unhandled residual; in fact Keycloak disables redirect following
  by default, and the real hazard is a deployment that re-enables it. Say that, and name the setting (see
  P0-6).

- [ ] **P6-3 · Stale comment in `openid/verify/LWSCredentialVerifier.java:207-213`** about avoiding a
  Titanium version conflict — Titanium is already in the shaded JAR. Fix when P2-1 lands.

- [ ] **P6-4 · Document the `ADMIN_EDIT` requirement** for `lws_jwk` and for any WebID attribute, in
  `README.md`, `INSTALL.md` and `docs/walkthrough-ssi-cid.md`, with an explicit note that a user-writable
  attribute is an identity-spoofing vector (see P0-2).

- [ ] **P6-5 · Add a conformance statement:** which MUSTs each suite implements, which are deferred to the
  relying party (audience confinement), and which key types and RDF syntaxes are supported. That is what
  an implementer integrating against `lws-authn` actually needs, and it is currently spread across
  `README.md` and `COMPLIANCE.md`.

- [ ] **P6-6 · Missing repository files:** `SECURITY.md` (how to report a vulnerability — this is a
  credential-verification library), `CONTRIBUTING.md`, `CHANGELOG.md`.

- [ ] **P6-7 · Licence headers.** `LICENSE` is Apache-2.0, but every source file carries only
  "Copyright Erich Bremer". Add `SPDX-License-Identifier: Apache-2.0` to each file.

---

## What the review found to be correct

Recorded so a later pass doesn't re-litigate it:

* Every vocabulary IRI is right. `lws:OpenIdProvider`, `did:service`, `did:serviceEndpoint`,
  `sec:authenticationMethod`, `sec:verificationMethod`, `sec:controller`, `sec:publicKeyJwk` and
  `sec:JsonWebKey` all match the `https://www.w3.org/ns/cid/v1` context and the 2026-08-21 LWS
  Vocabulary, as does the `rdf:JSON` datatype for `publicKeyJwk`.
* The OpenID CID's service map is **conformant without an `id`** — CID 1.0 makes it OPTIONAL (P2-6 is a
  nicety, not a fix).
* `LWSSubMapper.transformUserInfoToken`'s `getOtherClaims().put("sub", …)` matches what Keycloak's own
  `AbstractPairwiseSubMapper` does; it is not a bug.
* Redirect-based SSRF is not exploitable in a default deployment (P0-6 is about the non-default case).
* The SPARQL parameterisation against attacker-controlled `sub` / `iss`, the SAML XSW defences
  (reference-covers-own-ID plus single-assertion plus direct-child navigation), the XXE hardening, the
  did:key algorithm pin, the explicit `exp`-required rule in all four verifiers, and the `commons-codec`
  relocation are all sound and test-backed.
