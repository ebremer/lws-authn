# Changelog

Notable changes to `lws-authn`. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project does not yet publish semantic versions (see *Versioning* at the end).

Item ids like **P0-3** refer to [`TODO.md`](TODO.md), which carries the full reasoning for each change.

---

## [Unreleased] — toward 0.3.0

Brings the provider up to the LWS editor's drafts of **21 September 2026** (`w3c/lws-protocol` at
`3ddc642`). Two changes to the drafts since 0.2.0's baseline touch this provider, and implementing the
second properly exposed four places where the self-signed CID verifier did not follow Controlled
Identifiers 1.0 §3.3, which that suite cites normatively for selecting a key.

> ### If you are upgrading an existing deployment, read this section
>
> Nothing is removed. The `/lws-ssi-did-key` endpoint keeps answering exactly as before. But the
> self-signed CID verifier is **stricter**, and a document that used to verify may now fail — see
> *Behaviour that got stricter* below. And the JAR is now `lws-authn-0.3.0-SNAPSHOT.jar`: the tree is
> unreleased work, and the filename says so.

### What changed in the specifications

- **The self-signed `did:key` suite was discontinued** on 18 September 2026 (w3c/lws-protocol#229),
  "in favor of lws10-authn-ssi-cid, which subsumes this specification by specifying a generalization of
  the mechanism described here".
- **The self-signed CID suite now works with DIDs**: it "is designed to work with subject identifiers
  that use HTTPS URIs as well as DID URIs", because a DID document extends a controlled identifier
  document (w3c/lws-protocol#233, DID 1.1 §5).
- **Core added `subject_identifier_types_supported`** to LWS authorization server metadata
  (w3c/lws-protocol#227). **Not applicable here**: `lws-authn` is not an LWS authorization server and
  publishes no such metadata; the field belongs in `lws-server`.
- The rest — ETag rules, the `lws10-index` rename, `lws:StorageResource`, straight quotes — is storage
  or editorial and touches nothing in this provider. The OpenID and SAML suites have not changed.

### Added

- **DID subjects in the self-signed CID suite** (`/lws-ssi-cid/verify`). The subject is resolved to its
  DID document and then validated exactly as an HTTPS subject's controlled identifier document is:
  - **`did:key`** — expanded locally into the document the did:key Method v0.9 defines (a `Multikey`
    method, referenced from `authentication`). No network access. The identifier must be canonically
    encoded and of a supported key type (Ed25519, P-256, P-384, P-521).
  - **`did:web`** — fetched from `https://<domain>[:port][/path]/did.json` (or
    `/.well-known/did.json`) through the same SSRF-guarded, redirect-refusing, size- and time-bounded
    client an HTTPS subject uses. The method's rules are enforced before anything is fetched: a domain
    name, never an IP address; a port only as `%3A`. The document must be served as a DID or JSON media
    type and its `id` must be the DID (`subjectIdMatches`).
  - Any other method is refused by name (`subjectDereferenced: false`, "supported: did:key, did:web").
  - A DID document is read by the JSON rules of its representation, not through a JSON-LD processor:
    DID 1.1 is a Candidate Recommendation and its context is not published at a stable URL, so there is
    nothing trustworthy to bundle yet.
- **`Multikey` verification methods** (CID 1.0 §2.2.2), in HTTPS documents as well as DID documents.
  A `publicKeyMultibase` is decoded by the same codec as a did:key; a value carrying a *secret*-key
  header is refused by name. The derived key is pinned to the one JWS algorithm its type signs with.
- **A `kid` may name the method by its full identifier** — `did:key:z…#z…`, `https://id.example/a#k1` —
  which is the verification method identifier CID 1.0 §3.3 retrieves by and the usual `kid` for a DID;
  or by its fragment with a leading `#`. Only a method of the subject's own document can match.
- **`verificationMethodActive`**, a new check: the selected method is neither `revoked` ("MUST NOT be
  used") nor `expires`d (CID 1.0 §2.2).

### Deprecated

- **The self-signed `did:key` suite and its endpoint, `/lws-ssi-did-key/verify`.** It still verifies
  exactly as before — including a `did:key` credential with no `kid`, which that suite never required —
  and now marks every response, success or refusal, per RFC 9745:
  ```
  Deprecation: @1789689600
  Link: <../lws-ssi-cid/verify>; rel="successor-version"
  Link: <https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/>; rel="deprecation"
  ```
  Keycloak logs a warning at startup. **Move callers to `/lws-ssi-cid/verify`**, adding a `kid`
  (`<did>#<multibase>`), then switch the old endpoint off with
  `--spi-realm-restapi-extension--lws-ssi-did-key--enabled=false`. No removal date is set.

### Behaviour that got stricter

Each is a requirement of CID 1.0, which the self-signed CID suite cites for selecting the key, and
each may reject a document that used to verify. Check your issuers' documents before rolling this out.

- **Only methods the `authentication` relationship names can authenticate.** CID 1.0 §2.3: "Verification
  methods that are not associated with a particular verification relationship cannot be used for that
  verification relationship." The verifier used to accept any method *defined* under
  `verificationMethod`, even one only `assertionMethod` or `keyAgreement` referred to. Referencing a
  method from `authentication` by URL — the way did:key documents do it — now works as CID 1.0 §3.3
  says it should, on both the JSON-LD and the compact-JSON path.
- **A method's `id` must be in the subject's own document** (CID 1.0 §3.3 takes the document from the
  identifier). Methods written with no `id` are still tolerated and selectable by their JWK's `kid`.
- **`revoked` and `expires` are honoured** (`verificationMethodActive`), and a value that is not an
  `xsd:dateTimeStamp` makes the method unusable rather than silently current.
- **A `publicKeyJwk` carrying private members is not a usable verification method** (CID 1.0 §2.2.3).
  This provider already refused to *publish* one (P0-1); it now refuses to *verify* against one too.
- **`ES256`/`ES384`/`ES512` are pinned to P-256/P-384/P-521** (RFC 7518 §3.4), for every JWT suite. A
  JCA verifier accepts, say, a SHA-512 signature from a P-256 key; that is valid ECDSA and not ES512.

### Changed

- **Version `0.3.0-SNAPSHOT`.** The JAR is `lws-authn-0.3.0-SNAPSHOT.jar`, so a build of this tree cannot
  be mistaken for the 0.2.0 release (commit `e539362`, which is untagged — see *Versioning*).
  `LwsAuthIT` now takes the JAR's path from Failsafe and CI uploads `target/lws-authn-*.jar`, so neither
  needs editing at the next release.
- The multibase/did:key codec moved from `ssididkey` to a new `did` package, since the self-signed CID
  suite now depends on it; JDK signature verification moved to `jose.JwsSignatures`.

### Tests

190 unit tests (was 144), 25 in `LwsAuthIT` (was 23). New: DID syntax, the did:web URL mapping against
the method's own examples, did:key expansion against the did:key Method's worked example, the multibase
codec against the did:key and CID 1.0 test vectors, every CID 1.0 method rule above on both parsing
paths, and did:key credentials verified end to end through the self-signed CID suite for every supported
key type. `LwsAuthIT` gains a did:key credential through `/lws-ssi-cid` (Ed25519 exercising Keycloak's
EdDSA provider) and the deprecation headers.

---

## [0.2.0] — 2026-09-03

Everything below has landed since the `lws-authn-0.1.0` tag (14 June 2026). It is a large change: the
whole repository was reviewed against the current W3C LWS Working Drafts and the specifications they
incorporate by reference, and the security, conformance and robustness findings were closed.

> ### If you are upgrading an existing deployment, read this section
>
> Four changes will break a working integration. None can be avoided by not configuring anything —
> the defaults themselves changed, deliberately, because the old defaults were unsafe.

### ⚠ Breaking

- **The four `…/verify` endpoints now require the caller to authenticate** (P0-3). Previously anonymous.
  Verification is expensive out of proportion to the request — a single POST makes the server
  dereference a URL the caller chose, run Discovery against it and fetch its JWKS, all *before* the
  signature is known good, because that is the order the cold-trust algorithm requires. Open to
  anonymous callers that is request amplification, a network-probe oracle and a cheap denial of service.
  - Default mode is `bearer`: present a Keycloak access token for the realm.
  - `LWS_AUTHN_VERIFY_ACCESS=public` restores the previous behaviour exactly, for a deployment where
    the endpoints are already unreachable from the internet.
  - Rate limiting (60/min per caller) applies in every mode, including `public`.
- **`Authorization` means the caller's credential, not the credential under test** — except in
  `public` mode, where it still falls back to the old meaning. **Send the credential being verified in
  the `credential` form field.** If you were passing it as `Authorization: Bearer …`, either move it to
  the body or set `public` explicitly.
- **A rejected credential is now `200` with `"valid": false`, not `401`** (P3-1). RFC 9110 §15.5.2
  requires a `401` to carry a `WWW-Authenticate` challenge, and the status said the wrong thing anyway:
  the request *was* authorized and the server answered it. `401`/`403` now mean only "you may not use
  this endpoint" and always carry a challenge. **Read `valid`, not the status.**
- **Validation got stricter, so credentials that used to pass may now fail** (P1, P2). Each of these
  was a `MUST` that was not enforced:
  - OpenID: `azp` is required; a missing LWS client identifier now fails closed.
  - Self-signed CID and `did:key`: `iat` is required; `exp` is required (a missing `exp` used to mean
    "never expires", making a captured token replayable forever); a non-empty `crit` header is refused.
  - `did:key`: the identifier must be **canonically encoded** — the decoded key is re-encoded and must
    reproduce it, so one key cannot have two identifiers.
  - Self-signed CID: a verification method is usable only if it is a `JsonWebKey` the subject
    **controls**, and its `alg` is pinned to the published key.
  - SAML: `<Issuer>` is required; `<samlp:Status>`, the IdP certificate's own validity, and the bearer
    `<SubjectConfirmationData>` (method, `Recipient`, `NotOnOrAfter`) are all checked.
  - All suites: the `typ` header, when present, must name a JWT.

### Added

- **A real configuration surface** (P3-6). Every tunable is read from the provider's `Config.Scope`,
  then a system property, then an environment variable, then a compiled-in default: the SSRF
  allow-list, outbound timeout and response cap, clock skew, CID cache lifetime and rate limit, a
  deployment-wide required `audience`, and an `enabled` flag that a **realm attribute** can override
  per realm. Full table in `README.md`; deployment guidance in `INSTALL.md` step 9e. Every environment
  variable that worked before still works.
- **Audience binding.** Every `/verify` accepts an `audience` parameter, and the OpenID one a
  `client_id` that turns on OpenID Connect Core §3.1.3.7 steps 3–5 — what stops a token minted for one
  relying party being replayed at another. A deployment can require an audience for every request
  rather than trusting each caller to pass the optional parameter.
- **`did:key` P-384 and P-521**, alongside Ed25519 and P-256. Curve parameters now come from the JDK
  instead of hand-transcribed constants.
- **Proper JSON-LD processing** (P2-1). Controlled identifier documents go through Jena's JSON-LD 1.1
  reader, so a conforming document from any implementation verifies whatever shape it is written in —
  aliased terms, an `@graph` wrapper, referenced rather than embedded verification methods. Contexts
  resolve from copies **bundled in the JAR**, never fetched.
- **Cacheable, properly negotiated identity documents** (P2-2/3/4). `cid/{userId}` honours `Accept`
  q-values, answers `406` when nothing on offer is acceptable, and carries `Vary`, `ETag` and
  `Cache-Control`.
- `SECURITY.md`, `CONTRIBUTING.md`, this changelog, and SPDX headers on every source file (P6-6, P6-7).
- CI hardening (P5-5): least-privilege `permissions`, actions pinned by commit SHA, CodeQL,
  dependency review, Dependabot, SBOM upload, and a JDK 25 job asserting the class files are still
  Java 21.

### Fixed

- **SSRF is enforced at name resolution, not in front of it** (P0-5). `SsrfGuard` is installed as the
  DNS resolver of the verifiers' own HTTP client, so the addresses approved are exactly the addresses
  connected to — closing the DNS-rebinding window between check and connect. That client also disables
  redirect following outright, rather than depending on
  `spi-connections-http-client-default-allow-redirects` staying `false` (P0-6).
- **Verify responses no longer leak internal detail** (P0-4): no upstream status codes, resolved
  addresses or exception text. Rejections carry a `traceId`; the detail is logged at `DEBUG`.
- **Private key material is never published** (P0-1). A `lws_jwk` value carrying `d`, `p`, `q`, `dp`,
  `dq`, `qi`, `k`, `oth`, or a `kty` of `oct`, is refused outright and logged — not trimmed, because
  the key is already compromised and quietly serving its public half would hide that.
- **SAML signature wrapping and XXE** (P0-7/8): claims are read only from the cryptographically covered
  assertion, located by direct-child navigation; DTDs are disallowed independently of any caller
  configuration.
- **A `kid` is percent-encoded into the verification method's IRI fragment** (P3-3). A `kid` containing
  a space or `#` used to produce an IRI Jena refuses to serialize, returning `500` for the whole
  document — including every other key on that user. Every method now has the `id` CID 1.0 requires.
- **Unrecognised content types are refused, not parsed as Turtle** (P3-5), so an HTML error page no
  longer comes back as a misleading Turtle syntax error.
- **Every non-result response body is serialized rather than concatenated** (P3-2), with one shape —
  `{"error", "error_description"}` — across every endpoint and status.
- **The shaded JAR ships what it should** (P4). Libraries Keycloak already provides are no longer
  bundled unrelocated; where Jena needs a newer version it is bundled *and relocated*. This was found
  by the integration test, which caught a packaging change that broke Jena's Turtle writer.
- A trailing-whitespace WebID attribute is trimmed before it becomes the `sub` claim.

### Testing

144 unit tests (21 before this work) and 23 in `LwsAuthIT` against a real Keycloak 26.7.3 container
(10 before). Roughly half the integration tests now assert a *rejection*: a verifier that wrongly
rejects gets reported by its users, and one that wrongly accepts does not.

---

## [0.1.0] — 2026-06-14

First release. All four LWS 1.0 authentication suites as Keycloak 26 providers: OpenID Connect,
Self-signed Controlled Identifier, SAML 2.0, and self-signed `did:key` — with the WebID `sub` protocol
mapper, hosted controlled identifier documents for the two suites that need them, and a verifier for
each suite.

---

## Versioning

**0.2.0 is the first release whose version actually identifies it.** Until this release `pom.xml` read
`0.1.0` while the `lws-authn-0.1.0` tag pointed at the first commit, so the JAR this tree produced was
*named* `lws-authn-0.1.0.jar` without being the 0.1.0 release — harmless while the only consumer was
the author, a trap the moment two builds existed on one machine. The build now produces
`lws-authn-0.2.0.jar`, so a deployed artifact can be identified by its filename again.

**Identifying an already-deployed instance**, which by definition predates this fix and is named
`lws-authn-0.1.0.jar` whichever code it holds: send an anonymous `POST …/verify`. A `401` carrying a
`WWW-Authenticate` header is 0.2.0; a verification result is the older code.

Tag each release commit `lws-authn-<version>` so the tag, the POM and the JAR filename agree.
