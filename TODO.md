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

> ### P0, P1, P2, P3, P4, P5 and P6 are done
>
> More precisely: every item those bands contained **at review time**, plus **P6-8**, added
> afterwards. Two added items are still open — **P0-10** (the live deployment still runs pre-P0 code)
> and **P4-7** (no `.gitattributes`). P0-10 is the highest priority item in this file: it is the only
> one with consequences outside the repository. **P1-C6** was checked off in the P1 pass without its
> fix being made; P3-3 finished it, and its entry now says so.
>
> `mvn clean verify` is green: **144 unit tests** (21 before this work started) and **23** in
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
> ### P3 (all seven items)
>
> - **A rejected credential is now a `200` with `"valid": false`** on all four suites, not a bare
>   `401`. A `401` means *the caller* was refused and always carries a challenge. **This is a
>   breaking change for a client that read the status instead of the body.**
> - **Every non-result body is serialized, not concatenated**, and every one has the same shape:
>   `{"error", "error_description"}`, whichever endpoint and whichever status produced it.
> - **A real configuration surface.** `Settings` / `ServerSettings` / `EndpointSettings` read every
>   tunable from `Config.Scope`, then a system property, then an environment variable: the SSRF
>   allow-list, outbound timeouts and response cap, clock skew, CID cache lifetime and rate limit, a
>   deployment-wide required audience, and an on/off flag that a **realm attribute** can override per
>   realm. The full table is in `README.md`.
> - **The two `cid/{userId}` endpoints are one implementation** (`http/CidEndpoint`), rate limited,
>   with a uniform response shape and an explicit written decision about why they are unauthenticated.
> - A `kid` is percent-encoded into the verification method's IRI fragment, so a `kid` with a space or
>   a `#` in it no longer 500s the whole document; the verifier matches raw *and* decoded fragments.
>   This also finished **P1-C6**, which was checked off with its fix unmade and deferred the encoding
>   half to P3-3: every published method now has the `id` CID 1.0 requires.
> - An unrecognised `Content-Type` on a dereferenced document is refused by name instead of being fed
>   to the Turtle parser.
>
> ### P5 (all five items)
>
> - **`LwsAuthIT` went from 10 tests to 23**, and roughly half of the new ones assert a *rejection*.
>   The host-side server is now a general fixture server, and an `OpenIdFixture` stands up a complete
>   third-party OpenID Provider from it so each test can break exactly one document — a discovery
>   `issuer` mismatch, an absent `jwks_uri`, a JWKS with no matching `kid`, `HS256` against an RSA key,
>   a subject that declares no provider, a token minted for another relying party.
> - **`assertRejected` names the check that must fail.** An assertion that only looked at
>   `valid: false` keeps passing once the branch it was written for stops being reachable.
> - **The port-8080 constraint is documented where it cannot be missed** and now fails fast with the
>   reason, instead of surfacing as a two-minute container-start timeout.
> - **CI is hardened:** a least-privilege `permissions:` block, every action pinned by commit SHA,
>   CodeQL, `dependency-review-action` on pull requests, Dependabot for the bumps that SHA pinning
>   would otherwise freeze, SBOM upload, and a JDK 25 job that asserts the class files are still Java 21.
>
> ### P6 (all eight items)
>
> - **`COMPLIANCE.md` is rewritten**, and is now the conformance statement P6-5 asked for rather than
>   a second overlapping document: per suite, every requirement enforced — naming the field that
>   appears in the response's `checks` object, so a claim in it can be tested against a real response —
>   what is deferred to the relying party, the supported key types and syntaxes, and a *Known
>   divergences* table whose every row names the item id carrying its reasoning.
> - **`SECURITY.md`, `CONTRIBUTING.md` and `CHANGELOG.md` added.** The changelog leads with a
>   **⚠ Breaking** section, because the defaults themselves changed; `SECURITY.md` says what is
>   deliberate rather than a bug, so a reporter does not spend a weekend on the SAML trust model.
> - **`INSTALL.md` gained step 9f**, which actually *sets* the `ADMIN_EDIT` attribute policy. It was
>   previously only a line in the closing checklist, met after the realm was already configured.
> - **All 63 source files now carry `SPDX-License-Identifier: Apache-2.0`** (19 did).
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

- [ ] **P0-10 · The live deployment is still running pre-P0 code, and the upgrade is breaking.**
  *(Added after the P0–P2 work landed. Not a code defect — the code is fixed; this is the fix not yet
  being where it matters.)* `https://ebremer.com/auth` (realm Halcyon, client `lws-app`) predates all of
  it. Deploying the current JAR changes behaviour in ways that surface as silent `401`s on traffic that
  works today:
  - the `…/verify` endpoints are authenticated by default (P0-3);
  - `Authorization` now carries the **caller's** credential, not the credential under test (P0-3);
  - `azp`, `iat` and `kid` became mandatory (P1-O1, P1-C1/C3, P1-D1), so a third-party issuer omitting
    any of them stops verifying;
  - controlled identifier documents must carry `id`, `type` and `controller` (P1-C4/C5/O3).

  There is also a reason to *want* the upgrade rather than merely survive it: until the P2 `KeyType`
  fix, **no EC-signed credential could be verified in any suite**. If anything there uses ES256 — the
  algorithm every LWS suite example uses — the self-signed-CID verify endpoint has never actually
  worked.

  **Do:** write `UPGRADING.md` and roll out in stages. Deploy first with
  `LWS_AUTHN_VERIFY_ACCESS=public` so access control is unchanged, confirm live traffic still verifies,
  then tighten to `bearer`. The claim-level strictness has no opt-out, so audit what issuers actually
  send *before* deploying, not after.

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
  `SelfSignedControlledIdentifierDocument` added `id` only when a `kid` was present, and fell back to a
  blank node in the RDF serialization. CID 1.0: a verification method's `id` MUST be a string
  conforming to URL syntax.
  **Done — with P3-3, which this item deferred the encoding half to.** This was checked off in the P1
  pass with the fix not actually made; finishing P3-3 finished it. Every published method now has an
  `id`: the `kid` supplies the fragment when it can be percent-encoded into one, and when it cannot —
  absent, blank, over-long, or not well-formed text — the position stands in as `#key-<n>`, the option
  this item named. Positional, so it shifts if keys are added or removed; a verifier selects by the
  JWK's own `kid` first in any case. No blank-node verification method is emitted any more.

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

- [x] **P3-1 · `/verify` returns 401 with no `WWW-Authenticate` header.**
  All four providers returned `Response.Status.UNAUTHORIZED` for a credential that did not verify.
  RFC 9110 §15.5.2: *"The server generating a 401 response MUST send a `WWW-Authenticate` header
  field."* The status was also semantically wrong — the *request* was authorized; the *submitted
  credential* was not valid.
  **Done:** a verification outcome is always `200 OK` with `{"valid": …}` in the body. `401`/`403` now
  mean only "the caller may not use this endpoint" and always carry a challenge (`VerifyAccess`),
  `400` means the request could not be read, `404` means the suite is disabled here, `429` means rate
  limited. `LwsAuthIT.anInvalidCredentialIsTwoHundredWithValidFalse` checks all four suites answer
  `200` with `valid:false` **and** send no challenge.
  **Breaking:** a client that read the status rather than `valid` will now see `200` for a rejected
  credential. The status table is in `README.md` under "What each status means".

- [x] **P3-2 · JSON built by string concatenation.**
  Every "missing credential" body, the 404, the 406 and `VerifyAccess`'s denials were string literals
  with a message interpolated in. Every caller passed a constant, so nothing was broken — but it was
  one edit from emitting malformed JSON.
  **Done:** `http/JsonResponses` builds them all through `JsonSerialization`, with one shape
  (`{"error", "error_description"}`) across every endpoint and status — which P3-7 wanted anyway. The
  `WWW-Authenticate` header, assembled the same way, now escapes its `quoted-string` values.
  `JsonResponsesTest` round-trips a description full of quotes, backslashes and newlines.

- [x] **P3-3 · An unencoded `kid` can produce an invalid IRI and a 500 from the CID endpoint.**
  `SelfSignedControlledIdentifierDocument` built `id + "#" + kid` with no escaping; a `kid` containing
  a space, `#` or `/` yielded an IRI Jena rejects when serializing — taking down the whole document,
  including every other key on that user.
  **Done:** `jose/KeyIdFragment` percent-encodes everything outside RFC 3986 `unreserved`, and refuses
  (rather than mangles) a `kid` that is blank, absurdly long, or contains an unpaired surrogate; a
  refused `kid` leaves the method unidentified — a blank node in RDF, no `id` in JSON-LD — which is
  what a JWK with no `kid` already produced. `SelfSignedCidVerifier.selectByKid` compares a method's
  fragment both raw and percent-decoded, so this provider's own documents and other implementations'
  both resolve.

- [x] **P3-4 · SPARQL predicates hardcoded as strings instead of the constants that exist for them.**
  **Already fixed** by the P1 work: `SelfSignedCidVerifier.collectFromRdf` binds `SEC_AUTHENTICATION`,
  `SEC_VERIFICATION_METHOD`, `JSON_WEB_KEY_TYPE`, `SEC_CONTROLLER` and `SEC_PUBLIC_KEY_JWK` as IRI
  parameters of a `ParameterizedSparqlString`, alongside the subject. Nothing was left to do here.

- [x] **P3-5 · Unknown content types are parsed as Turtle.**
  `RdfParsing.parseRdf` defaulted to `Lang.TURTLE` for any unrecognised `Content-Type`; combined with
  the `{`-sniff in `isJsonLd`, an HTML error page reached the Turtle parser. It failed closed, but the
  reported error said "Turtle syntax error at line 1" when the truth was "that URL does not serve a
  controlled identifier document".
  **Done:** `RdfParsing.requireSupported` runs *before* the sniff, so a declared content type can no
  longer be overridden by a body that happens to start with a brace, and a type Jena does not know
  throws `UnsupportedSyntaxException` naming it. Both verifiers catch it separately from the generic
  failure and report the media type — public information the remote server chose to advertise. Only a
  document declaring *nothing* still falls back to Turtle: that is a guess about silence rather than a
  contradiction of what the server said.

- [x] **P3-6 · The SPI provides no configuration surface.**
  `init(Config.Scope)` was empty in all four factories (the P0 work had since wired `VerifyAccess`
  through it), and the SSRF allow-list was readable only from a JVM system property or environment
  variable. There was no supported way to set timeouts, clock skew, expected audiences or cache
  lifetimes, or to disable an endpoint per realm.
  **Done:** a `config` package. `Settings` is the single lookup — scope, then system property, then
  environment, then default — and `isSet` distinguishes "not configured" from "configured to the
  default". `ServerSettings` holds what static utility code reads (`SsrfGuard`'s allow-list,
  `OutboundHttp`'s timeout and response cap, `JwsChecks`'s clock skew, shared with the SAML
  `<Conditions>` window); each factory *contributes* to it from its own scope, so a setting one
  provider names applies to all four and a provider that says nothing leaves it alone. Out-of-range
  values are clamped. `EndpointSettings` holds the per-provider ones: `enabled`, a deployment-wide
  required `audience` used when a request names none, `cid-cache-seconds` and `cid-rate-limit`, plus
  the `VerifyAccess` policy. **Per realm:** `enabled` also honours a realm attribute
  `lws.authn.<providerId>.enabled`, which is the one setting realms of a server sensibly differ on.
  Every environment variable that worked before still works. Full table in `README.md`; 13 tests in
  `SettingsTest`.

- [x] **P3-7 · The CID endpoints are unauthenticated and uncached.**
  Uncached was already fixed by the P2 work (`Vary`, `ETag`, `Cache-Control`). What was left was the
  explicit decision the item asked for.
  **Done — and the decision is that they stay unauthenticated.** A controlled identifier is a URL other
  people dereference; a verifier meets the subject there before any trust exists in either direction,
  so there is no credential it could present, and an authenticated identity document is not a
  dereferenceable one. What that costs is enumeration, so it is bounded rather than closed: a uniform
  response shape (document, `404`, `406`, `429` — all `application/json` of one shape, nothing but the
  status distinguishing them), user ids that are random UUIDs, and a rate limit — `cid-rate-limit`,
  default 600/minute per caller, an order of magnitude above the verify limit because this is a cheap
  local read. A deployment that does not want to host identifiers at all sets `enabled=false`. Both
  endpoints are now one implementation, `http/CidEndpoint`, which carries the reasoning in its javadoc;
  `LwsAuthIT.everyRefusalIsJsonOfTheSameShape` checks the uniform shape end to end.

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

- [ ] **P4-7 · No `.gitattributes`, so line endings are whatever each clone decides — and the shell
  scripts break on Linux.** *(Added after the P4 pass, from a Windows-specific review.)*
  Git for Windows sets `core.autocrlf=true` at system level (neither local nor global config chooses
  it). Git *stores* `scripts/*.sh` with LF, so the repository content is correct and Linux CI is
  unaffected — but a Windows working tree has CRLF, including the scripts.

  Verified: same Keycloak image, same bash 5.1.8, two scripts differing only in line endings — the LF
  one exits 0, the CRLF one fails with `env: 'bash\r': No such file or directory`, exit 127. Git Bash
  runs CRLF scripts happily, which is exactly why this is invisible from a Windows box; `bash -n` passes
  too, so a syntax check does not catch it either. `README.md` documents `bash scripts/lws-demo.sh` as
  the primary way to try each suite, so anyone taking a Windows checkout into WSL, a container or a
  Linux host hits it.

  The latent half is worse than the immediate one: with no `.gitattributes` the outcome depends on each
  contributor's `core.autocrlf`, so someone with `input` or `false` can commit CRLF *into* the
  repository, at which point Linux CI breaks for everyone.

  **Do:** add at the root —
  `* text=auto` and `*.sh text eol=lf` — then `git add --renormalize .` once. `text=auto` normalises to
  LF in the repository whatever the local setting; `eol=lf` on `*.sh` forces LF in the *working tree*
  too, even on Windows. It also silences the CRLF warning printed on every commit.

---

## P5 — Tests and CI

- [x] **P5-1 · The verifiers' *network* half is only ever exercised on the happy path.**
  Everything between the outbound fetch and the signature was untested in its failure modes — the
  direction where a bug is silent, because a verifier that wrongly rejects gets reported and a verifier
  that wrongly *accepts* does not.
  **Done, where the item said to do it:** the host-side server already running in `LwsAuthIT` is now a
  general fixture server (a route map and one catch-all handler, so a test registers whatever documents
  it needs), and an `OpenIdFixture` stands up a complete third-party OpenID Provider — CID document,
  discovery document, JWKS — from it. Each negative test breaks exactly one of the three and asserts
  the verifier notices *that* one thing. `LwsAuthIT` went from 10 tests to 23; the container start is
  still the whole cost.
  **`assertRejected` names the check that must fail**, not just `valid: false`: an assertion that only
  looked at `valid` would keep passing after the branch it was written for stopped being reachable —
  a fixture that simply failed to load satisfies it. `aThirdPartyOpenIdProviderVerifies` is the control
  that keeps the negatives honest: the same fixture, unbroken, must verify.

- [x] **P5-2 · Add a negative test for every P0/P1/P2 rule.** The six that were still missing, all on
  the network half, now exist in `LwsAuthIT`:
  | Case | Failing check |
  |---|---|
  | Discovery declares a different `issuer` | `issuerDiscoveryMatches` |
  | Configuration has no `jwks_uri` | `jwksResolved` |
  | JWKS publishes no key matching the token's `kid` | `jwksResolved` |
  | `HS256` token against the provider's RSA key (algorithm confusion) | `jwksResolved` |
  | Subject's CID declares no `OpenIdProvider` service | `openIdProviderServiceLocated` |
  | ID Token minted for another relying party (§3.1.3.7 steps 3–5) | `audienceContainsClient` / `audienceMatched` |

  Plus three the item did not list but the same fixture made cheap: a self-signed-CID method with a
  foreign `controller` (`verificationMethodFound`), one published `use: enc`, and one whose `alg` is
  not the token's (`verificationMethodUsableForSigning`).
  **Worth recording about the HS256 case:** it is refused at *key selection* — `resolveSigningKey`
  will not return a key whose type cannot produce the declared algorithm — so `algorithmMatchesKey`,
  which exists for exactly this attack, is never reached. It stays as defence in depth for a future
  path that selects a key some other way; the test asserts the rejection, not which of the two layers
  caught it.

- [x] **P5-3 · `LwsAuthIT` pins host port 8080.**
  **Done: documented prominently, which is the option this item offered first, and made to fail
  usefully.** The constraint is now the `LwsAuthIT` class javadoc rather than a comment halfway down
  `startKeycloak`, and it explains the *reason* — the OpenID verifier dereferences its own issuer, so
  the issuer URL has to resolve to Keycloak from both this JVM and inside the container, and
  `http://localhost:8080` bound straight through is the only spelling that does. `requirePort8080()`
  probes the port before the container starts and throws with that explanation, instead of letting the
  symptom be a two-minute health-check timeout.
  **Why not the random port.** `ExtendableKeycloakContainer` hardcodes 8080 in three places — the
  exposed port, the HTTP wait strategy and the log-wait regex — so moving Keycloak's own port means
  replacing all three and owning startup detection. That trades a loud, immediate, obviously-fixable
  failure for a subtle flaky one. The javadoc records this so the next reader does not rediscover it.
  The suite still cannot run in parallel with itself; that is stated too.

- [x] **P5-4 · `LwsAuthIT` never asserts a rejection.** Every suite now has at least one, so a verifier
  that degrades to "accept everything" fails CI: OpenID (six cases above), self-signed CID (three),
  `did:key` (a token signed by a key the DID does not name → `signatureValid`), and SAML (a Response
  that does not verify against a supplied certificate). P3-1's
  `anInvalidCredentialIsTwoHundredWithValidFalse` covers all four again at the HTTP level.

- [x] **P5-5 · CI hardening.** `.github/workflows/ci.yml` had no `permissions:` block, pinned actions by
  tag, ran no scanning, and built only on JDK 21.
  **Done:**
  - A top-level `permissions: contents: read`, with `security-events: write` granted only to the CodeQL
    job. Without the block a workflow inherits the repository default, which for an older repository is
    often read-write on everything.
  - **Every action pinned by commit SHA**, with the release recorded in a trailing comment. A tag is a
    mutable pointer: whoever controls the action repository can move `v4` at any time and every
    workflow referencing it runs the new code on the next build, unreviewed.
  - **CodeQL** (`java-kotlin`, `security-and-quality`) as its own job, building explicitly rather than
    via autobuild so it does not re-run the tests.
  - **`dependency-review-action`** gating pull requests at `fail-on-severity: high`, plus
    **`.github/dependabot.yml`** for the continuous half — weekly Maven and github-actions updates.
    Dependabot matters more than usual here precisely *because* the actions are SHA-pinned: a pin is
    what stops a moved tag, but it also means a security fix in an action never arrives on its own.
    Keycloak is excluded from the grouped updates — this provider is compiled against a specific server
    version and the IT pins the matching container image, so moving it is a decision, not an update.
  - **A JDK 25 job** that builds and then reads the class-file version back out of `target/classes`,
    failing unless it is 65 (Java 21). Development happens on 25 while the artifact targets 21, and
    `maven.compiler.release` silently not applying is exactly the kind of regression that would
    otherwise surface as a `LinkageError` inside a customer's Keycloak.
  - The **SBOM the build already produces** (`cyclonedx-maven-plugin`, bound to `package` since P4) is
    now uploaded per build, so what shipped can be matched against an advisory later without rebuilding
    the commit.

---

## P6 — Documentation

- [x] **P6-1 · `COMPLIANCE.md` is stale.** It was dated 2026-07-09, called the suites *"unofficial
  proposals"*, and its "Residual issues" and "Suggested next steps" were the pre-P0 review — every one
  of them since closed.
  **Done: rewritten from scratch, and merged with P6-5** so there is one authoritative document rather
  than two overlapping ones. Front matter restated against the spec matrix above (Working Drafts of
  3 and 21 August 2026; CID 1.0 is a Recommendation). The "Gaps / softness" tables are gone, replaced
  by a *Known divergences and deliberate choices* table where every row is a decision that names the
  item id carrying its reasoning — so the two documents cannot drift apart silently again.

- [x] **P6-2 · `README.md`'s SSRF section overstates the residual risk on redirects.**
  **Already fixed by P0-6.** The section now says the verifiers' own client disables redirect following
  outright, names `spi-connections-http-client-default-allow-redirects` and its `false` default, and
  says the hazard is a deployment re-enabling it — which is exactly what this item asked for. Recorded
  rather than re-fixed.

- [x] **P6-3 · Stale comment in `LWSCredentialVerifier`** claiming the compact JSON-LD reader exists to
  avoid coupling to a Titanium version conflicting with Keycloak's.
  **Done.** That was true before P2-1 and P4-2; the conflict was settled by *relocating* Titanium into
  the shaded JAR, not by avoiding it. The javadoc now says what the method is actually for: the
  fallback for a document naming an `@context` this provider does not bundle, which `RdfParsing` refuses
  to fetch. Reading the standardized shape by name is the only interpretation available without those
  term definitions.

- [x] **P6-4 · Document the `ADMIN_EDIT` requirement.**
  Mostly already covered — `README.md`, both walkthroughs and `INSTALL.md`'s hardening checklist all
  named it, with the spoofing framing.
  **What was missing, and is the point of the item:** `INSTALL.md` had no step that actually *set* it.
  A reader following the guide configured a realm, never touched the attribute policy, and met the
  requirement only in a checklist at the end — by which time `lws_jwk` values were already being
  silently dropped. **New step 9f** sets it, with the `kcadm.sh` command, the console path, a
  verification command, the narrower user-profile alternative, and a table of what each attribute
  actually controls. The checklist now links to it.

- [x] **P6-5 · Add a conformance statement.** **Done as the rewritten `COMPLIANCE.md`** rather than a
  third document, since P6-1 was rewriting it anyway and a separate file would have been the same
  content in a second place. It states, per suite: every requirement enforced (naming the field that
  appears in the response's `checks` object, so a claim in the document can be tested against a real
  response), what is deferred to the relying party and why, the supported key types and RDF syntaxes,
  and the deliberate divergences. `README.md` now links to it as the thing to read before integrating.

- [x] **P6-6 · Missing repository files.** All three added:
  - **`SECURITY.md`** — how to report, what is in scope, and what is *deliberate* rather than a bug:
    the SAML verifier trusting the caller's certificate, identifier enumeration on `cid/{userId}`, and
    a deployment configured with `ENABLED` attributes. Naming those up front is what stops a reporter
    spending a weekend on a non-issue.
  - **`CONTRIBUTING.md`** — build, test, and the conventions that are not obvious from the code: why
    comments cite specifications, why a new rule needs a *negative* test, which layer to test at (with
    the two bugs only the container caught as the argument), and the shaded-JAR dependency rules.
  - **`CHANGELOG.md`** — with an explicit **⚠ Breaking** section for the upgrade path, since the
    defaults themselves changed. It also records that `pom.xml` still reads `0.1.0` while the
    `lws-authn-0.1.0` tag points at the first commit, so the JAR this tree builds is *named* 0.1.0 but
    is not 0.1.0 — harmless with one consumer, a trap the moment two builds exist on one machine.

- [x] **P6-7 · Licence headers.** `LICENSE` is Apache-2.0 but only 19 of 63 source files said so in a
  form any tool could read.
  **Done: all 63 now carry `SPDX-License-Identifier: Apache-2.0`.** Files with an existing header had
  the tag inserted after the copyright line, leaving the prose untouched; the 19 test files with no
  header at all got a minimal one. `CONTRIBUTING.md` states the requirement for new files. This is what
  makes the licence machine-readable to a scanner, an SBOM consumer or a downstream redistributor — the
  SBOM the build already produces is otherwise describing files that assert nothing.

- [x] **P6-8 · The demo realm teaches a client identifier that is not a URI.**
  `examples/lws-demo-realm.json` uses `lws-app`, and LWS core §4.1 says the client identifier SHOULD be
  a URI. The verifier requires `azp` but not that it be a URI, so the example everyone copies modelled
  the weaker form silently.
  **Decision: the demo keeps `lws-app`, and now says why.** It is also a *Keycloak* client id — what
  you type into the console, pass as `client_id` in a token request, and see in every Keycloak
  tutorial. Making it a URL would teach the LWS point at the cost of obscuring the Keycloak one, in
  the document whose job is to get someone from nothing to a working identity. §4.1 is a SHOULD, and
  both forms verify.
  **Done:** `docs/walkthrough-openid.md` explains it where the reader first meets `azp` in a decoded
  token, and says to prefer a URI in production, that `https://app.example.com/` is a perfectly good
  Keycloak client id, and that nothing else needs changing because `client_id`, `aud` and `azp` all
  follow it. `README.md` and `COMPLIANCE.md` § *Known divergences* record the same. The realm, scripts
  and `LwsAuthIT` are untouched — changing them would have churned the integration test for a SHOULD.
