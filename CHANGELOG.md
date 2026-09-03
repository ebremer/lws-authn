# Changelog

Notable changes to `lws-authn`. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project does not yet publish semantic versions (see *Versioning* at the end).

Item ids like **P0-3** refer to [`TODO.md`](TODO.md), which carries the full reasoning for each change.

---

## [Unreleased]

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

`pom.xml` still reads `0.1.0`, and the `lws-authn-0.1.0` tag points at the first commit — so the JAR
this tree builds is named `lws-authn-0.1.0.jar` but is **not** the 0.1.0 release. That is fine while
the only consumer is the author, and a trap the moment two builds exist on one machine.

**If you are deploying alongside an existing instance, check what you actually have** — compare the
JAR's checksum, or look for a behaviour this changelog lists as breaking (an anonymous `POST …/verify`
returning `401` with a `WWW-Authenticate` header means the new code; returning a verification result
means the old). Bumping the version before the next deployment would remove the ambiguity.
