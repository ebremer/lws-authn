# TODO — `lws-authn`

Prioritized backlog from a **full code review** of this repository on **6 October 2026**, including an
evaluation against the **W3C Linked Web Storage specifications as they stood on 5 October 2026**.

- **Code reviewed:** `master` at `edda85b` (version `0.3.0-SNAPSHOT`), every file under `src/`,
  `pom.xml`, CI, Docker, scripts, the demo realm and `docs/`.
- **Specification baseline:** `w3c/lws-protocol` at `ef02548` (5 October 2026) — see
  [Specification baseline](#specification-baseline-5-october-2026).
- **Tree state:** `mvn clean package` green on JDK 25 (GraalVM CE 25.0.4) — **179 unit tests, 0
  failures**. `LwsAuthIT` was **not** run (no Docker in the review environment). GitHub CI is green on
  `master` at `edda85b`; **every pull-request run since 1 October fails** (R-40).
- **Method:** five parallel review slices (OpenID suite; self-signed CID suite with DIDs and JOSE;
  SAML suite; network/HTTP/config/RDF infrastructure; build, CI, tests and docs). Most findings were
  reproduced with throwaway probes against the built JAR and Keycloak 26.7.4's own classes. Every
  `High` item and every P0/P1 item was re-checked against the source while compiling this file.

Each item says **where**, **what is wrong** (quoting the specification for conformance items), **how it
fails**, and **what to do**. Tags: severity `High` / `Medium` / `Low` / `Info`; effort `S` (hours) /
`M` (a day or two) / `L` (more); confidence *demonstrated* (reproduced with a probe), *verified* (traced
end to end in the code) or *plausible* (not fully traced).

Item ids are **`R-nn`** so they cannot collide with the ids of the earlier reviews (`P0-1` … `P6-8`,
`S-1` … `S-18`), which code comments, tests, `CHANGELOG.md` and `COMPLIANCE.md` cite. Those reviews are
kept, unchanged, in the [Archive](#archive--reviews-of-2-to-30-september-2026) at the end of this file;
the four items they left open are carried forward here (R-15, R-43, R-50, W-1).

---

## Summary

**Conformance.** Nothing in the specifications changed between the last review (`9b03b32`, 28
September) and 5 October that bears on this provider: the one new commit, `ef02548`, makes JSON Patch
the baseline `PATCH` format, which is storage-server business. The authentication text in core and in
the OpenID, SAML and self-signed CID suites is the text of 21 September. **But the code is not fully
compliant with that text**, and `docs/COMPLIANCE.md` overstates it in places. MUST-level gaps found:

| Suite | Gap | Item |
|---|---|---|
| Self-signed CID | "The `aud` claim MUST include the target authorization server" is only checked when an audience is configured or supplied; otherwise any `aud` — including `[""]` — passes | R-16 |
| OpenID | `aud` and `iat` are REQUIRED ID Token claims (OIDC Core §2, incorporated through §3.1.3.7) and are not enforced | R-17 |
| OpenID, SSI-CID | "a valid controlled identifier document with an `id` value equal to the subject identifier": the topmost `id` is not checked on the JSON-LD/RDF path (only "some triple is about `sub`"); valid CIDs with no `@context`, or served as `application/cid`, are refused | R-18, R-19 |
| SSI-CID | CID 1.0 §2.2 revocation/expiry fail open on a non-string or multi-valued `revoked`/`expires` | R-06 |
| SAML | Core §4.1 "subject … MUST be a URI", "issuer … MUST be a URI": NameID and Issuer are never checked | R-20 |
| SAML | SAML Core §2.5.1: multiple `<AudienceRestriction>` are ANDed, and an unknown condition MUST make the assertion invalid; both fail open | R-21 |
| SAML | "the signature … MUST be validated as described in SAML Core, section 5": §5.4.2's single `<ds:Reference>` and §5.4.4's transform restrictions are not enforced — a signature that excludes `<Subject>` by XPath transform verifies with a substituted subject | R-22 |

**Security.** Four `High` denial-of-service issues are reachable by **any user of the realm** — the
default `bearer` access mode requires no role — and run before any signature is checked: no overall
fetch deadline (R-01), a circuit breaker that an attacker can hold open against any host (R-02),
quadratic CPU in DID/CID key handling (R-03), and a 95 MB allocation from an 8-byte RDF-Thrift body
(R-04). The two controls meant to contain abuse are themselves weak: the breaker is the lever in R-02,
and the rate-limit key is spoofable behind the documented reverse proxy (R-10). Separately, a realm
**access token verifies as an LWS ID Token credential** (R-05), and plain `http` is accepted for every
key-bearing fetch (R-07).

**Operations.** Keycloak 26.7.5 (30 September, 14 security fixes) and 26.8.0 are out (R-14); the docs
tell operators to set runtime options at `kc.sh build`, where Keycloak silently drops them — including
`role` and `audience` (R-12); and the dependency-review CI job fails every pull request (every run since 1 October), so
Dependabot updates are stuck (R-40).

**Counts:** 15 items in P0, 10 in P1, 14 in P2, 12 in P3, 7 watch items.

---

## Specification baseline (5 October 2026)

| Document | Latest published version on 5 October 2026 | Editor's draft |
|---|---|---|
| Linked Web Storage Protocol 1.0 (core) | W3C Working Draft **21 September 2026** | `ef02548`; authentication text unchanged since 21 September |
| LWS 1.0 Authn Suite: Self-signed Identity (Controlled Identifiers) | W3C Working Draft **21 September 2026** | unchanged since 21 September |
| LWS 1.0 Authn Suite: OpenID Connect | W3C Working Draft 3 August 2026 | unchanged |
| LWS 1.0 Authn Suite: SAML 2.0 | W3C Working Draft 3 August 2026 | unchanged |
| LWS 1.0 Authn Suite: Self-signed Identity using did:key | **Discontinued Draft, 29 September 2026** | discontinued 18 September in favour of the self-signed CID suite |
| Linked Web Storage Vocabulary | W3C Group Note Draft 14 July 2026 | — |
| Controlled Identifiers (CID) 1.0 | W3C Recommendation, 15 May 2025 | — |
| Decentralized Identifiers (DIDs) 1.1 | W3C Candidate Recommendation Snapshot, 5 March 2026 | context URL still answers `300` |

Commits since the last review (`9b03b32`): only `ef02548` (#255, JSON Patch baseline for `PATCH` —
storage-side). Open pull requests that could matter here later, none merged: #256 (RFC 9728 protected
resource metadata for authorization-server discovery — storage/AS side), #96 (a Web-CID profile for
agent identification). See *Watch*.

---

## Compliance matrix (as of 5 October 2026)

✅ meets · ⚠️ partial · ❌ gap · — not applicable. Line numbers are at `edda85b`.

### Core — Authentication credential data model (LWS core, WD 21 September 2026)

| Requirement | OpenID | Self-signed CID | SAML |
|---|---|---|---|
| subject REQUIRED, "MUST be a URI" | ✅ `sub` required; must dereference as http(s) | ✅ only http(s), `did:key`, `did:web` resolve | ❌ NameID any string (R-20) |
| issuer REQUIRED, "MUST be a URI" | ✅ required; `https` not enforced (R-07) | ✅ equals `sub` | ❌ Issuer any string (R-20) |
| client REQUIRED, "SHOULD be a URI" | ✅ `azp` required | ✅ `client_id` required | ✅ `Recipient` required |
| audience restriction RECOMMENDED | ✅ optional, checked when asked | see suite (MUST) | ✅ always required (stricter; R-39) |
| "MUST be signed"; asymmetric RECOMMENDED | ✅ HS\* never accepted | ✅ HS\* never accepted | ✅ signature required |
| suite token type URI | ✅ `…token-type:id_token` | ✅ `…token-type:jwt` | ✅ `…token-type:saml2` |

Core *Authorization* (authorization-server metadata, token exchange, access tokens, storage-side
validation) — **not applicable**: this provider is not an authorization server (COMPLIANCE divergence 9).

### OpenID Connect suite (WD 3 August 2026)

| Requirement | Status | Evidence / item |
|---|---|---|
| "MUST NOT use `none`" | ✅ | `LWSCredentialVerifier.java:101-107` |
| `sub` / `iss` / `azp` carry subject / issuer / client | ✅ | `:125-146` |
| "Any audience restriction … MUST use the `aud` claim" | ✅ | only `aud` is read |
| "the validator MUST dereference the `sub`" | ✅ | `:150`; no caching (R-26) |
| "MUST be formatted as a valid controlled identifier document with an `id` value equal to the subject identifier" | ⚠️ | topmost `id` unchecked on the processor path (R-18); context-less and `application/cid` documents refused (R-19) |
| locate a service with `serviceEndpoint` = `iss` and type `lws:OpenIdProvider` | ✅ | parameterized SPARQL, `:412-422` |
| "MUST perform OpenID Connect Discovery to locate the public portion of the JWK" | ⚠️ | discovered `issuer` matched exactly ✅; `https` not required (R-07); key selection ignores `use`/`alg`, RSA size (R-27) |
| "MUST be validated as described by OpenID Connect Core Section 3.1.3.7" | ⚠️ | issuer ✅, signature ✅, `exp` ✅; `aud` ∋ client only when the caller passes `client_id`; `aud`/`iat` REQUIRED by Core §2 not enforced (R-17); ES\* signature length (R-24); nonce/acr/auth_time not applicable |
| token type `urn:ietf:params:oauth:token-type:id_token` | ✅ | `LWSConstants.java:43` |
| Security considerations (RFC 9700; OIDC Core §16) | ❌ | access tokens accepted as ID Tokens (R-05) |
| Privacy: verifiers "encouraged to cache controlled identifier documents" | ❌ | three fetches per verification (R-26) |

### Self-signed Identity using Controlled Identifiers (WD 21 September 2026)

| Requirement | Status | Evidence / item |
|---|---|---|
| "MUST NOT use `none`" / "MUST reject any tokens using … `none`" | ✅ | `SelfSignedCidVerifier.java:134-140` |
| `sub`, `iss`, `client_id` "MUST all use the same URI value" | ✅ | `:158-164` |
| "The `aud` claim MUST include the target authorization server" | ❌ | unchecked without a configured or supplied audience; `[""]` counts as present (R-16) |
| "MUST include an `exp`" / "MUST include an `iat`" | ✅ | `JwsChecks.java:142-157`, `:274-280`; future `iat` accepted (R-28) |
| "the verifier MUST dereference the `sub`" | ⚠️ | ✅ https, `did:key`, `did:web`; cleartext `http` accepted (R-07) |
| valid CID with `id` equal to the subject | ⚠️ | R-18, R-19; `subjectIdMatches` reported `true` unconditionally (`:352`) |
| "MUST validate all claims described by the authentication credential data model" | ✅ | |
| "MUST use the `kid` … to identify a verification method" per CID 1.0 §3.3 | ⚠️ | `authentication` only, in-document references, controller = subject ✅; id-less methods selectable, kid precedence (R-23) |
| signature "MUST be validated as described in RFC 7515, Section 5.2" | ⚠️ | non-canonical base64url header bypasses the `crit` check; ES\* length not enforced (R-24) |
| "current time is before … `exp`"; leeway MAY | ✅ | 60 s, configurable |
| token type `urn:ietf:params:oauth:token-type:jwt` | ✅ | `SsiCidConstants.java:74` |
| DID subjects (DID 1.1 §5.1.2) | ✅ | `did:key` local, `did:web` over guarded HTTPS; other methods refused by name (divergence 7) |
| CID 1.0 §2.2: a revoked method "MUST NOT be used" | ⚠️ | fails open (R-06) |
| CID 1.0 §2.2: method `id`/`type`/`controller` REQUIRED; "MUST NOT contain multiple verification material properties" | ⚠️ | R-23 |
| Privacy: cache controlled identifier documents | ❌ | R-26 |

### SAML 2.0 suite (WD 3 August 2026)

| Requirement | Status | Evidence / item |
|---|---|---|
| "SAML tokens used as authentication credentials MUST be signed" | ✅ | `SamlCredentialVerifier.java:114-119` |
| `saml:NameID` / `saml:Issuer` / `Recipient` carry subject / issuer / client | ✅ | all three required; not URI-checked (R-20) |
| "Any audience restriction … MUST use the `saml:Audience` assertion" | ⚠️ | only `saml:Audience` read ✅; restrictions OR-ed instead of AND-ed (R-21) |
| trust relationship with the issuing IdP, "established out-of-band" | ⚠️ | caller supplies the certificate per request (divergence 5, challenged in R-25) |
| signature "MUST be validated as described in SAML Core, section 5" | ⚠️ | Reference must be `#ID` ✅, claims read only from the covered element ✅; single Reference, transforms, algorithms not enforced (R-22) |
| token type `urn:ietf:params:oauth:token-type:saml2` | ✅ | `SamlConstants.java:28` |
| SAML2-SEC (incorporated): XXE, Status, certificate validity | ✅ | DTDs disallowed `:338-349`; Status `:103-111`; certificate window `:91-96` |
| SAML Core §2.5.1.1: unknown conditions → Invalid/Indeterminate → "MUST be rejected" | ❌ | R-21 |

### Documents this provider publishes

| Document | Status | Notes |
|---|---|---|
| OpenID CID (`/lws/cid/{id}`) | ✅ | matches the suite's example; named `#openid-provider` service; negotiation, `Vary`, `ETag`, `Cache-Control` |
| Self-signed CID (`/lws-ssi-cid/cid/{id}`) | ⚠️ | matches the suite's example; private JWK members refused; duplicate method ids possible (R-33) |

---

## P0 — Security: fix before the verify endpoints face untrusted callers

"Untrusted" includes every user of the realm: the default `bearer` mode accepts any realm access token
(R-11), and every item from R-01 to R-04 runs **before** a signature is checked, so no valid credential
is needed.

- [x] **R-01 · Outbound fetches have no overall deadline; a trickling or endless response stalls every
  verification server-wide.** `High` · security/DoS · `M` · *demonstrated*
  `net/OutboundHttp.java:98-113` sets only connect, pool-wait and per-read socket timeouts; the guarded
  client is one static pool of 16 connections, 4 per route (`:72-73`). Socket timeout is per read, so a
  server sending one byte every 4.9 s never trips the 5 s default. When the 256 KiB cap trips, Keycloak's
  `SafeInputStream` throws and try-with-resources `close()` **drains the rest of the body**. Probes: an
  endless chunked body was still being read after 15 s and 1.1 GB with a 2 s timeout; 16 trickling
  fetches exhausted the pool, and a fetch to a healthy host then failed with
  `ConnectionPoolTimeoutException`.
  **Do:** a hard per-request deadline (schedule `abort()` on the request); on cap overflow
  `abortConnection()` instead of `close()`; refuse an oversized `Content-Length` before reading; bound
  concurrent fetches per target host and per caller. Add trickle and endless-body tests to
  `OutboundHttpClientTest` (its `keepsTheResponseSizeCap` never sends an oversized body).
  **Done:** `OutboundHttp.fetch(url, accept, session)` replaces Keycloak's `SimpleHttp` in both
  verifiers, and `LwsSimpleHttp` is gone. A daemon timer aborts the request at `http-deadline-millis`
  (default 10 s, clamped 100 ms–120 s), which shuts the socket whatever the request is doing — waiting
  for a pooled connection, connecting, or blocked in a read; a declared `Content-Length` over the cap is
  refused before reading, and the body is read by hand and the request aborted the moment it passes the
  cap; a non-`200` body is not read at all. One caller (`VerifyAccess.callerKey`) may have at most
  `http-max-concurrent-per-caller` fetches in flight (default 4, clamped 1–64); one more is refused at
  once with `CallerBusyException` rather than queued for the pool. Session mode now refuses redirects
  per request too. The OpenID verifier's JWKS fetch also gained the status check it never had.
  `OutboundHttpClientTest` adds a trickling body, an endless body (and asserts the server stops being
  read), a stalled server, a declared gigabyte, and the per-caller bound; R-02 is the breaker half.

- [x] **R-02 · Any caller can hold the per-host circuit breaker open, and it re-arms itself.**
  `High` · security/DoS · `S` · *verified + demonstrated*
  `OutboundHttp.java:194-239`. `recordFailure` runs on failures that say nothing about the host's
  health — any non-200 (a 404 for a path the attacker chose), a wrong `Content-Type`, a parse error, a
  `subjectIdMatches` mismatch — and also when the breaker itself refuses the call: `requireClosedCircuit`
  throws `HostUnavailableException`, the verifier's `catch (Exception)` calls `recordFailure` again, and
  every failure pushes `windowEndsAt` another 10 s out. Five unsigned JWTs with
  `sub=https://<this-keycloak>/realms/r/lws/cid/nope` take down verification of every hosted-WebID
  credential for as long as any traffic arrives at least every 10 s; `iss=https://accounts.google.com/x`
  does the same to a third-party OP. Without an attacker: all self-dereferences come from Keycloak's own
  address, share one `cid-rate-limit` bucket, and the resulting `429`s count as failures. JWKS failures
  are recorded against the discovery host, so a failing JWKS host never trips its own breaker.
  **Do:** count only transport failures (connect error, timeout, 5xx); never count a refusal by the
  breaker itself; don't extend the window while open (half-open after it lapses); key on
  scheme+host+port; use a per-URL negative cache for 404s; record JWKS failures against the JWKS host.
  **Done, with one change of plan:** the breaker now counts only failures that say the *origin* cannot
  be reached — `UnknownHostException`, `ConnectException` (refused), `ConnectTimeoutException` and
  `SSLHandshakeException` — and not timeouts during the read or 5xx, which this item had proposed
  counting. Both depend on the path, which the caller chooses: a slow endpoint or one that answers 500
  can be found on many healthy origins, so counting them would have left the attack open. A slow or
  hostile server is bounded by R-01 instead. A pool wait (`ConnectionPoolTimeoutException`, a subclass
  of the connect timeout) and a deadline abort are excluded. Bookkeeping moved into `OutboundHttp.fetch`
  — the verifiers no longer call `recordFailure`/`recordSuccess`, which are now package-private test
  seams — so a breaker refusal is never recorded, and any answer from the origin clears it. Once open
  the window is fixed (a late failure from a fetch already in flight does not extend it), and the key is
  `scheme://host:port`. JWKS failures therefore count against the JWKS origin. `OutboundHttpCircuitTest`
  runs on a test clock (refusals and late failures do not extend; per-origin keys; the classification),
  and `OutboundHttpClientTest` shows ten 404s leave the origin open and a refused port trips it.

- [x] **R-03 · Quadratic CPU in DID/CID key handling: one request can burn minutes.**
  `High` · security/DoS · `M` · *demonstrated*
  - `did/DidKey.java:343-362` — `base58Decode` is O(n²) `BigInteger` arithmetic with no length cap;
    `decodeMultibase` (`:144`) is reached for any `publicKeyMultibase` and any `did:key`. A
    250 000-character value took **18 s**, and fits under the 256 KiB response cap.
  - `ssicid/verify/SelfSignedCidVerifier.java:644-705` — the SPARQL has four `OPTIONAL`s and returns the
    cross product of multi-valued `publicKeyJwk`/`publicKeyMultibase`/`revoked`/`expiration`; `seen` is
    updated only on success, so a failing method is re-decoded on every row. A **36 KiB** Turtle CID took
    **271 s**; growth is quadratic, so 256 KiB means hours.
  - Reference resolution re-walks the whole document per string reference (`findById`, `:822-841`):
    a 163 KiB `did:web` document with 8 000 unresolvable references took 30 s.
  **Do:** cap multibase length before decoding (a public key is ≈ 50–140 characters) and cap DID
  length; mark a method `seen` whether accepted or rejected; select optional values per method and
  refuse a method with more than one; resolve references through one id→node index; overall work budget
  per verification.
  **Done.** `DidKey.decodeMultibase` refuses a value over `MAX_MULTIBASE_LENGTH` (256 characters; the
  longest supported key is 95) before decoding, and `base58Decode` says it must be bounded by its caller.
  `Dids.methodOf` refuses a DID over `MAX_DID_LENGTH` (1 024), and its syntax check is now a character
  class plus a scan of each `%` — the repeated alternation recursed once per character and overflowed
  the stack, so this also closes R-09's DID case. `collectFromRdf` selects `DISTINCT ?m ?type` only and
  reads each method's values one property at a time; a method with two values for a property, or a
  non-literal one, is unusable — which is also R-06's RDF half (R-06's JSON half is still open).
  `collectFromJson` resolves references through an id index built once by an iterative walk (first map
  in document order wins, as before). Six regression tests (`DidKeyTest`, `DidsTest`,
  `VerificationMethodRulesTest`), each confirmed to fail against the previous code — one by taking
  22 s. Not done: an overall work budget per verification; the caps make it unnecessary for now.

- [x] **R-04 · The RDF parser accepts any syntax Jena knows, including binary RDF-Thrift: 8 bytes → 95 MB.**
  `High` · security/DoS · `S` · *demonstrated*
  `rdf/RdfParsing.java:76-84` and `:116-129` gate on `RDFLanguages.contentTypeToLang(ct) != null`, so a
  `sub` served as `application/rdf+thrift` (also TriG, N3, RDF/JSON, TriX, RDF-Protobuf) is parsed. The
  body `1C 18 E5 80 80 2D` — valid UTF-8, so it survives `asString()` — makes libthrift allocate ~94 MB
  and return an empty model without error; 64 concurrent parses on a 1 GB heap produced 33
  `OutOfMemoryError`s, which can land on any server thread.
  **Do:** accept exactly the syntaxes the `Accept` header asks for (Turtle, N-Triples, RDF/XML, JSON-LD,
  plus `application/json` and `application/cid` — R-19) and throw `UnsupportedSyntaxException` for
  everything else; consider excluding the Thrift/Protobuf readers from the shaded JAR.
  **Done.** `RdfParsing` reads a declared type only if it is in `READABLE` (`text/turtle`,
  `application/n-triples`, `application/rdf+xml`) or is `application/ld+json` / `application/json`;
  `requireSupported`, `isJsonLd` and `parseRdf` all use that table instead of
  `RDFLanguages.contentTypeToLang`. `RdfParsingTest.refusesRdfSyntaxesNobodyAskedFor` sends the
  eight-byte Thrift body and six other Jena-readable types, and fails against the previous code;
  `readsEverySyntaxTheVerifiersAskFor` keeps the four that matter. `application/cid` is left to R-19,
  which also needs context injection to make it useful. Not done: excluding the Thrift/Protobuf readers
  from the shaded JAR — unreachable now, so it is a size question rather than a security one.

- [x] **R-05 · A realm access token verifies as an LWS ID Token credential (token substitution).**
  `Medium` · security · `S` · *verified*
  `jose/JwsChecks.java:133` accepts `typ: at+jwt` — the RFC 9068 marker that says "this is an access
  token" — for both JWT suites, defeating the explicit typing RFC 8725 §3.11 exists for. And Keycloak
  puts `typ: JWT` in the header of access **and** ID tokens alike; only the payload `typ` claim (`Bearer`
  vs `ID`) tells them apart, and the verifier never reads it. `LWSSubMapper` writes the WebID into
  access tokens by default (`openid/LWSSubMapper.java:75`, `:115`; `examples/lws-demo-realm.json:43`
  sets `access.token.claim: true`), so a realm access token carries a WebID `sub`, `iss`, `azp`, `exp` —
  everything `/lws/verify` checks. A resource server that received a user's access token can replay it
  to an authorization server that verifies through this endpoint without `client_id`, and get
  `valid: true`.
  **Do:** remove `at+jwt` from the accepted types; in the OpenID verifier reject a payload `typ` that is
  present and not `ID`; default the mapper's access-token inclusion to off and say why in its help text
  and the demo realm. Add a negative test (`LwsAuthIT`: mint an access token, expect `typeIsJwt` or a
  new `tokenIsIdToken` check to fail).
  **Done.** `at+jwt` is out of `JwsChecks.ACCEPTED_TYPES` (both JWT suites). The OpenID verifier adds
  check `tokenIsIdToken` straight after `typeIsJwt`: a payload `typ` that is present and not `ID`
  (Keycloak's `TokenUtil.TOKEN_TYPE_ID`) fails — `Bearer`, `DPoP`, `Refresh`, `Logout` — and an absent
  one passes, since most providers omit it. `LWSSubMapper`'s *Add to access token* defaults to off, and
  `include` now takes the default per switch, so a mapper with no setting for it is off too (it used to
  treat "not set" as on); the demo realm and `lws-demo.sh` say `false`. Tests: `JwsChecksTest`,
  `LWSCredentialVerifierTest` (four payload types, the `at+jwt` header, and that `ID`/absent pass),
  `SelfSignedCidDidSubjectTest` (an otherwise valid `did:key` credential typed `at+jwt`), a new
  `LWSSubMapperTest`, each failing against the previous code; and
  `LwsAuthIT.anAccessTokenIsNotAnLwsCredential`, which presents a real realm access token — written,
  not yet run (no Docker here; see R-43).

- [x] **R-06 · Revocation and expiry of a verification method fail open.**
  `Medium` · security/spec-conformance · `S` · *verified*
  CID 1.0 §2.2: a revoked method "MUST NOT be used". On the JSON path (every `did:web` document, and the
  compact fallback) `firstText` (`SelfSignedCidVerifier.java:844-852`) returns `null` for any non-string
  value, which then means "never revoked": a JSON-LD value object
  `{"@value":"2000-01-01T00:00:00Z","@type":"xsd:dateTime"}`, an array or a number leaves the key usable
  (`:584-585`). On the RDF path `lexical` (`:859-861`) ignores an IRI value, and with two
  `sec:expiration` values (2000 and 2999) the first SPARQL row wins and the method stays active. This
  contradicts the code's own rule at `:587`: "An unreadable revocation date is not evidence that the key
  was never revoked."
  **Do:** a present `revoked`/`expires` that is not exactly one parseable date-time string or literal
  makes the method unusable, on both paths. Tests for each shape.
  **Done.** The RDF half went with R-03: a method with two values for one property, or a non-literal
  value, is unusable (`rdfAMethodWithTwoValuesForOnePropertyIsNotUsable`,
  `rdfANonLiteralRevocationIsNotUsable`). On the JSON path `revoked` and `expires` are now read by
  `soleDateTime` instead of `firstText`: a string, a JSON-LD value object with a string `@value`, or an
  array of exactly one of those is read as that date; JSON `null` is no value, as it is to a JSON-LD
  processor; anything else — two dates, an empty array, a number, a boolean, a node reference, a value
  object whose `@value` is not a string — makes the method unusable. `VerificationMethodRulesTest`
  covers each shape for both properties (`aRevocationThatIsNotAStringIsNotIgnored`,
  `aRevocationInAnotherShapeOfOneDateIsRead`); both fail against the previous code.

- [x] **R-07 · Plain `http` is accepted for every key-bearing fetch.**
  `Medium` · security/spec-conformance · `S` · *verified*
  `net/SsrfGuard.java:68` allows `http` and `https`; neither verifier checks the scheme of `sub`, `iss`,
  the discovery URL or `jwks_uri`. OpenID Connect Core §2: `iss` "is a case-sensitive URL using the
  https scheme"; Discovery 1.0 §3: `jwks_uri` "MUST use the https scheme"; the self-signed CID suite and
  `COMPLIANCE.md` speak of "HTTPS URIs". Anyone on the network path between Keycloak and an `http`
  subject, issuer or JWKS host can substitute keys and forge credentials for that identity. (`did:web`
  already forces `https`.)
  **Do:** require `https` for all four in both suites, and require `iss` to have no query or fragment;
  allow `http` only for hosts in `allowed-internal-hosts` (the demos and `LwsAuthIT` need it) and say so
  in `hardening.md`.
  **Done.** The rule is enforced where every fetch is checked: `SsrfGuard.verify` refuses plain `http`
  to a host that is not allow-listed, before any lookup, with `InsecureSchemeException` (a
  `BlockedException`); `secureOrAllowListed` states the rule once. That covers `sub` in both suites, the
  discovery URL and `jwks_uri`, and the client follows no redirects, so the URL checked is the URL
  fetched. On top, the OpenID verifier checks `iss` before anything is fetched — new check
  `issuerWellFormed`: an absolute URL with a host, no user information, query or fragment, https or an
  allow-listed http host — and both verifiers name the problem (`'sub' … is not an https URL`; `… names a
  jwks_uri that is not an https URL`) instead of the generic dereference error. Tests in `SsrfGuardTest`,
  `OutboundHttpClientTest`, `LWSCredentialVerifierTest` and `SelfSignedCidVerifierTest`; the
  internal-address tests in `SsrfGuardTest`, `GuardedDnsResolverTest` and `OutboundHttpClientTest` now
  use `https` URLs so they go on testing the address rather than the scheme. `LwsAuthIT`'s fixtures are
  all on its allow-listed hosts.

- [x] **R-08 · SSRF guard: special-purpose and address-embedding IPv6/IPv4 ranges pass.**
  `Medium` · security · `S` · *demonstrated (classification)*
  `net/SsrfGuard.java:133-158` relies on `InetAddress.is*` predicates plus a few ranges. Allowed today:
  NAT64 `64:ff9b::/96` (e.g. `64:ff9b::a9fe:a9fe` → 169.254.169.254) and `64:ff9b:1::/48`;
  IPv4-compatible `::127.0.0.1`; SIIT `::ffff:0:a.b.c.d`; 6to4 `2002::/16`; Teredo `2001::/32`;
  `100::/64`; `192.0.0.0/24`; `198.18.0.0/15`; `240.0.0.0/4`; `255.255.255.255`; the documentation
  ranges. NAT64 is real on IPv6-only cloud subnets with DNS64, where it reaches private IPv4 in the VPC.
  `hardening.md` claims "reserved" addresses are blocked.
  **Do:** unwrap the embedded IPv4 address of NAT64, compatible, SIIT, 6to4 and Teredo addresses and
  re-check it; block the listed ranges — or better, allow only global unicast (IPv6 `2000::/3` minus the
  IANA special-purpose registry). Extend `SsrfGuardTest` with each case.
  **Done, the better way.** `SsrfGuard.isInternal` now allows IPv6 only within `2000::/3`, less the
  not-globally-reachable blocks inside it (`2001::/23`, which holds Teredo and benchmarking;
  `2001:db8::/32`; `3fff::/20`; `5f00::/16`). IPv4-mapped, NAT64 `64:ff9b::/96` and 6to4 `2002::/16`
  addresses are judged by the IPv4 address they carry; everything else outside global unicast —
  IPv4-compatible, SIIT, local-use NAT64, `100::/64` — is refused with the rest. IPv4 follows a table of
  the IANA registry's not-globally-reachable blocks plus multicast and the deprecated 6to4 relay
  anycast; the JDK predicates stay in front as a backstop. Four new `SsrfGuardTest` cases, each case in
  this item's list among them, and one that the neighbours of every block stay reachable; three fail
  against the previous guard.

- [x] **R-09 · `StackOverflowError` from attacker-controlled nesting escapes every handler.**
  `Medium` · robustness/DoS · `S` · *demonstrated*
  The verifiers catch `Exception`, not `Error`, so each of these returns a `500` with an ERROR stack
  trace instead of `valid: false`, and skips the breaker bookkeeping:
  - SAML: 50 000 nested elements inside a signed assertion's `<Advice>` (≈ 350 KB) overflow in Keycloak's
    `XMLSignatureUtil` *before* signature validation on JDK 21, whose default `jdk.xml.maxElementDepth`
    is 0 (the Dockerfile builds on Temurin 21). JDK 25's default of 100 blocks it.
  - RDF: 12 000 levels of `[<p>` in Turtle (168 KB) or deeply nested JSON-LD under the size cap
    (`RdfParsing.java:174-187` catches only `RuntimeException`).
  - DIDs: the `(?:[…]|%XX)*` alternation in `did/Dids.java:65` recurses per character; a ~2 000-char DID
    overflows. *(Fixed with R-03: length cap and a non-recursive check.)*
  **Do:** set `jdk.xml.maxElementDepth` (e.g. 64) on the SAML `DocumentBuilderFactory`; pre-scan RDF and
  JSON for nesting depth; cap DID length and use possessive quantifiers or a hand scanner; cap the
  `credential` form parameter's length; catch `StackOverflowError` around parsing as a last resort.
  **Done.** Re-probed first, on JDK 25 and with `jdk.xml.maxElementDepth=0` to stand in for JDK 21:
  Turtle overflows at 5 000 levels of `[` or `(`; JSON-LD at 500 nested `@context`s (plain nested
  objects and arrays did not, and the compact JSON path stops at Jackson's own depth limit of 1 000);
  RDF/XML does not overflow at 50 000 even with no JDK limit, so it needs no scan; a JWT payload is
  bounded by Jackson. Fixes: `RdfParsing.requireShallow` counts brackets outside strings, IRIs and
  comments in one pass and refuses Turtle and JSON-LD deeper than `MAX_NESTING_DEPTH` (64) with
  `TooDeeplyNestedException`, which `parse` does not turn into a fall-back to the compact reader; both
  parsers also catch `StackOverflowError` as a backstop. `SamlCredentialVerifier` sets
  `maxElementDepth` to 100 on its own `DocumentBuilderFactory` — JDK 25's default, whatever the JDK or
  the system property says — and catches `StackOverflowError` as a backstop; the depth limit alone stops
  the overflow (checked by removing the catch). `VerifyAccess.refuseOversized` caps `credential` at
  256 KiB in all three endpoints with a `400`. Tests: `SamlVerifierTest.deeplyNestedElementsAreRefusedNotOverflowed`
  (sets the system property to `0`; overflowed before), three in `RdfParsingTest` (Turtle, JSON-LD,
  and brackets in strings, IRIs and comments that must not count), one in `VerifyAccessTest`.

- [x] **R-10 · The rate-limit key is spoofable behind the documented reverse proxy.**
  `Medium` · security/docs · `S` · *plausible (Quarkus forwarded-header parsing not run)*
  `verify/VerifyAccess.java:246-254` keys buckets on `ClientConnection.getRemoteAddr()`. `INSTALL.md:564`
  configures nginx with `$proxy_add_x_forwarded_for`, which *appends* to a client-supplied header; with
  `proxy-headers=xforwarded` Keycloak takes the left-most entry, which the client controls, so a random
  `X-Forwarded-For` per request is a fresh bucket each time. Without `proxy-headers`, every caller shares
  the proxy's one bucket. IPv6 callers get a bucket per /128, so a /64 is unlimited. R-01 to R-04 make
  this limit the main thing standing between a realm user and an outage.
  **Do:** document `proxy_set_header X-Forwarded-For $remote_addr;` plus `proxy-trusted-addresses`;
  bucket IPv6 by /64; add a per-*authenticated-principal* limit in `bearer` mode, which no header can spoof.
  **Done.** `VerifyAccess.callerKey` keys an IPv6 address by its `/64` (`addressKey`: an IPv4-mapped
  address is its IPv4 address; a string that is not an address literal is kept as it is and, being
  bracketed before parsing, never resolved). That key also bounds the CID endpoints and
  `OutboundHttp`'s in-flight limit. In `bearer` mode, once the token is authenticated, the same limiter
  takes a second permit under `user:<id>`, so rotating addresses no longer helps a realm user.
  `INSTALL.md` step 12 now overwrites `X-Forwarded-For` with `$remote_addr` and says why, step 9b sets
  `proxy-trusted-addresses=127.0.0.1,::1`, and `configuration.md` explains both; the CHANGELOG tells
  existing installs to make the same change. `VerifyAccessTest` covers the keys. Still *plausible*
  rather than demonstrated: which `X-Forwarded-For` entry Quarkus reports was not run, and with the
  header overwritten it no longer matters. `secret` mode still has only the address bucket: its callers
  share one secret, so a bucket per secret would throttle them all together.

- [x] **R-11 · Default access mode admits every realm user, and the role check reads stale claims.**
  `Medium` · security/decision · `S` · *verified*
  `VerifyAccess.java:171-184`: `bearer` mode authenticates any access token issued by the realm, for any
  client, with no audience check; `role` is unset by default, so any user — including a self-registered
  one, or the demo `alice` (R-13) — can drive outbound fetches. The role is read from the token's
  claims, so a revoked role keeps working until the token expires.
  **Decide:** require `role` (refuse to start the verify endpoints in `bearer` mode without one, or deny
  by default), and/or require tokens issued to a configured client. At minimum, `configuration.md` and
  `hardening.md` must say that `role` is effectively mandatory on any realm with untrusted users.
  **Decided and done: a role is required by default.** `role` now defaults to `lws-verifier`
  (`VerifyAccess.DEFAULT_ROLE`); `role=*` (`ANY_USER`) is the explicit opt-out to the old behaviour and
  logs a warning at startup. A realm with no such role refuses every bearer caller with `403
  insufficient_scope` and logs that once per realm. The role is checked with `UserModel.hasRole` —
  current mappings, composites and groups — and no longer read from the token: a revoked role stops
  working at once, and a caller with a lightweight access token (Keycloak's default for `admin-cli`,
  which the demo scripts use) is no longer refused for carrying no role claim. Not done: restricting
  callers to tokens issued to a configured client — with a role required, that adds little.
  The demo realm defines the role and grants it to `alice`; `lws-demo.sh`, `ssi-cid-demo.sh` and
  `did-key-demo.sh` create it if missing and grant it to the user they verify as (`VERIFY_ROLE`
  overrides the name). `VerifyAccessTest` covers the default, the override, `*`, and `holdsRole`;
  `LwsAuthIT.onlyAHolderOfTheVerifierRoleMayVerify` creates a user, shows `403` without the role, `200`
  with it, and `403` on the same token once it is revoked — written, not run (no Docker; R-43). **The
  demo scripts' new role step is untested here too** (no Keycloak). Breaking for every existing
  `bearer` deployment, which is why the CHANGELOG's upgrade box leads with it — including the live one
  (R-15).

- [x] **R-12 · Runtime options documented as `kc.sh build` flags are silently ignored by Keycloak.**
  `Medium` · security/docs · `S` · *verified in the docs; Keycloak behaviour checked in its CLI bytecode*
  `docs/configuration.md:41-43, 70-74` and `docs/INSTALL.md:317-320, 348-350` tell operators to pass
  `--spi-realm-restapi-extension--lws--access=…` (and `allowed-internal-hosts`, `role`, `audience`, …) to
  **`kc.sh build`**. Keycloak treats only SPI keys ending in `-provider`, `-enabled` or
  `-provider-default` as build-time; for anything else it logs "run time options were found, but will
  be ignored during build time" and does not persist it. An operator who sets `role` or `audience` that
  way runs without that control, with no error.
  **Do:** document these as `kc.sh start` options, `keycloak.conf` entries or `KC_SPI_…` environment
  variables; add a line to the INSTALL checklist that verifies the effective value (the provider could
  log its effective settings at `postInit`).
  **Done.** Every `kc.sh build --spi-…` in `configuration.md` and `INSTALL.md` (§9c, §9d, §9e) is now a
  `keycloak.conf` entry or a `kc.sh start` option, with a "Runtime, not build time" section saying why
  and what Keycloak prints; the one genuinely build-time key, `enabled`, says so. Each factory's
  `postInit` now calls `EndpointSettings.logEffective()`, which logs `lws-authn provider '<id>' settings
  in force: …` (access, role, rate limit, audience, CID cache and rate limit; a secret only as
  `secret=(set)`) and, once per start, `ServerSettings.describe()`. INSTALL §14 gains a checklist line
  to read them. `INSTALL.md` §9e also lists the two server-wide settings R-01 added. The `Settings` and
  `VerifyAccess` javadoc no longer say `kc.sh build`. `SettingsTest.describesWhatIsInForceWithoutTheSecret`.
  Not done: `KC_SPI_…` environment variables are not documented — the provider's own `LWS_AUTHN_*`
  variables already cover configuration from the environment, and the exact `KC_SPI_` spelling for the
  `--`-separated keys was not checked against Keycloak here.

- [x] **R-13 · The production install's "fast path" leaves a known-password user and a wildcard-redirect client.**
  `Medium` · security/docs · `S` · *verified*
  `docs/INSTALL.md:605-617` runs `scripts/lws-demo.sh` against the production server without setting
  `PASSWORD`, which creates realm `lws-demo`, user `alice`/`alice` and public client `lws-app` with
  `redirectUris: ["*"]`, `webOrigins: ["*"]` and the password grant; the production checklist
  (`:681-700`) never says to remove them. Anyone can mint alice's token — enough for the
  bearer-protected `/verify` (R-11) — and the wildcard redirect is an authorization-code theft vector.
  **Do:** require `PASSWORD` in the fast path; add "delete the `lws-demo` realm" to §14; label the demo
  realm JSON as demo-only and give it brute-force protection.
  **Done.** `lws-demo.sh` and `ssi-cid-demo.sh` default `PASSWORD` to `alice` only when `KC_URL` is
  `localhost` or `127.0.0.1`, and otherwise stop before any request with an example
  (`PASSWORD=$(openssl rand -base64 18)`); checked by running both against a remote and a local URL.
  The demo client — created by `lws-demo.sh` and in `examples/lws-demo-realm.json` — now has
  `standardFlowEnabled: false` and no redirect URIs or web origins: nothing used the browser flow, and
  the password grant is all the scripts and `LwsAuthIT` need. The demo realm has `bruteForceProtected`
  and a display name that says development only (JSON has no comments). INSTALL §13 passes a random
  `PASSWORD`, says to delete the realm afterwards and why — including a realm an earlier script left
  with `redirectUris: ["*"]` — and §14 lists "Demo realm gone". Not run against Keycloak here: the
  realm import with `bruteForceProtected` and without redirect URIs (R-43).

- [ ] **R-14 · Upgrade Keycloak: 26.7.4 is missing 14 security fixes.**
  `Medium` · dependency · `S` · *verified*
  Keycloak **26.7.5** (30 September 2026) fixes 14 security issues, including CVE-2026-18217 (SAML
  Redirect Binding parameter pollution), CVE-2026-89298 and CVE-2026-88770; **26.8.0** followed on 1
  October. `pom.xml:20`, `Dockerfile:13`, `LwsAuthIT.java:98` and nine docs pages pin 26.7.4, and
  `INSTALL.md:52` says the server version "**Must match**" `keycloak.version`, which discourages operators
  from taking patch releases.
  **Do:** move to 26.7.5 now (re-run the POM's provided/relocated-library check, as S-17 did); evaluate
  26.8.0 separately; reword to "same 26.x minor; apply patch releases"; put the version in one place
  (it is hard-coded in 17 files).

- [ ] **R-15 · The live deployment still runs pre-P0 code** (carried forward from **P0-10**).
  `High` · operations · `M` · *not re-verified from here*
  Unchanged from P0-10: `https://ebremer.com/auth` predates the P0–P3 work. The upgrade is breaking
  (authenticated verify endpoints, `Authorization` meaning the caller, `azp`/`iat`/`kid` required) and
  will be more so after this review's P1 items. **Do:** as P0-10 says — stage it with
  `LWS_AUTHN_VERIFY_ACCESS=public`, confirm live traffic verifies, then tighten — but deploy a build that
  already contains R-01 to R-05, R-11 and R-14, since the deployment is internet-facing.

---

## P1 — Specification conformance (MUST-level, as of 5 October 2026)

- [ ] **R-16 · Self-signed CID: "The `aud` claim MUST include the target authorization server" is not enforced
  by default** (challenges COMPLIANCE divergence 2). `Medium` · spec-conformance · `S` · *verified*
  `SelfSignedCidVerifier.java:283-297`: with no `audience` form parameter and no configured `audience`,
  only presence is checked — `aud: ["https://evil.example"]` returns `valid: true`, and so does `aud: [""]`;
  the `checks` object simply has no `audienceMatched`. Divergence 2 argues from core's *RECOMMENDED*
  audience, but in this suite it is a MUST, and a conforming credential always names its target, so
  requiring a match can never reject one. A credential minted for authorization server A is therefore
  accepted on behalf of B — exactly the replay the requirement exists to stop.
  **Do:** for `lws-ssi-cid`, refuse a verification with no known target (`400`, or `valid: false` with
  `audienceMatched: false` and a clear error), or at the very least never return `valid: true` without
  `audienceMatched`; reject blank `aud` values. Rewrite divergence 2 per suite. Breaking — CHANGELOG.

- [ ] **R-17 · OpenID: `aud` and `iat` are REQUIRED ID Token claims and are not enforced.**
  `Medium` · spec-conformance · `S` · *verified*
  `LWSCredentialVerifier.java:217-243` reads `aud` only when the caller passes `client_id` or `audience`,
  and never reads `iat`; a token with neither validates. OpenID Connect Core §2 lists `aud` and `iat` as
  REQUIRED and says `aud` "MUST contain the OAuth 2.0 client_id of the Relying Party"; §3.1.3.7 step 3,
  incorporated by the suite ("MUST be validated as described by …"), is a MUST. The self-signed suite
  already checks both (`audiencePresent`, `issuedAtPresent`). Divergence 2's reasoning covers *matching*
  an audience, not its *presence*.
  **Do:** always require a non-empty `aud` and an `iat`; reject `iat` beyond `now + skew` (R-28).
  Consider `aud ∋ azp` by default with an opt-out (some providers issue cross-client tokens where they
  differ). Fix the stale step numbering in the comment at `:217-220` (errata set 2 renumbered §3.1.3.7
  and made `azp` handling SHOULD/MAY).

- [ ] **R-18 · "a valid controlled identifier document with an `id` value equal to the subject identifier"
  is only loosely checked, in both JWT suites.** `Medium` · spec-conformance · `S` · *demonstrated*
  On the JSON-LD/RDF path the check is "some triple has `sub` as its subject"
  (`LWSCredentialVerifier.java:293-303`): a document whose topmost `id` is `https://other.example/doc`,
  nesting `{"id": sub, "service": …}` under `alsoKnownAs`, verifies; so does a bare `@graph`. In the
  self-signed verifier `subjectIdMatches` is reported `true` unconditionally (`SelfSignedCidVerifier.java:352`),
  and a mismatch caught by the compact fallback is reported as `subjectDereferenced: false` ("Failed to
  dereference") and counted against the host's breaker (R-02). CID 1.0: "If `controllerDocument.id` does
  not match the `controllerDocumentUrl`, an error MUST be raised." The comment at `:293-297` and
  `COMPLIANCE.md` ("on *both* the RDF and the JSON-LD path") claim the stronger check.
  **Do:** for JSON(-LD) bodies read the topmost `id`/`@id` from the raw JSON (resolved against the
  document URL) and require it to equal `sub` before RDF processing; report `subjectIdMatches` from what
  was actually compared; keep "fetch failed" and "wrong document" as distinct checks.

- [ ] **R-19 · Valid CIDs with no `@context`, or served as `application/cid`, are refused.**
  `Medium` · spec-conformance/interop · `S` · *demonstrated*
  CID 1.0 §4.2.1: "Implementations that do not intend to use JSON-LD MAY choose to not include an
  `@context`", and a consumer "MUST inject or append an `@context` property with a value of
  `https://www.w3.org/ns/cid/v1`". JSON-LD processing of a context-less document (CID 1.0's own Example 22
  shape) yields an empty — non-null — model, so the compact fallback never runs: the OpenID suite fails
  `subjectIdMatches`, the self-signed suite `verificationMethodFound`. CID 1.0 Appendix A registers
  `application/cid`, which `RdfParsing.requireSupported` (`:76-84`) refuses as "not an RDF syntax"; neither
  verifier's `Accept` header names it. Also: the compact fallback (`LWSCredentialVerifier.java:348-395`)
  turns a `type` array into `""` and reads only `serviceEndpoint[0]`, so adding one unbundled context to
  an otherwise valid CID changes the verdict.
  **Do:** inject the CID context when `@context` is absent; treat `application/cid` as JSON-LD and add it
  (and `application/json`) to `Accept`; make the fallback handle `type`/`serviceEndpoint` arrays like the
  processor path. Optionally offer `application/cid` from the CID endpoints.

- [ ] **R-20 · SAML: subject and issuer are not validated as URIs.**
  `Medium` · spec-conformance · `S` · *demonstrated*
  LWS core §4.1: subject "MUST be a URI", issuer "MUST be a URI". `SamlCredentialVerifier.java:144-166`
  accepts `NameID=alice` (the unit tests use exactly that), an email-format NameID, and `Issuer=idp`.
  SAML Profiles §4.1.4.2: the Issuer's `Format` "MUST be omitted or have a value of
  `urn:oasis:names:tc:SAML:2.0:nameid-format:entity`". `NameQualifier`/`SPNameQualifier` are dropped.
  `COMPLIANCE.md`'s core table implies these are enforced.
  **Do:** require an absolute URI for both (as `LWSSubMapper` already does for the WebID); reject an
  Issuer `Format` other than absent or `entity`; report the NameID `Format`. Fix the tests' fixtures.

- [ ] **R-21 · SAML `<Conditions>` processing fails open.**
  `Medium` · spec-conformance/security · `S` · *demonstrated*
  `SamlCredentialVerifier.java:394-402` flattens every `<Audience>` of every `<AudienceRestriction>`
  into one list; `:213` evaluates only the first `<Conditions>`; other condition elements are ignored.
  SAML Core §2.5.1.4: "multiple `<AudienceRestriction>` elements … each MUST be evaluated independently …
  [they] form a conjunction". §2.5.1.1: a condition that is not understood makes the assertion
  Indeterminate, and "An assertion that is determined to be Invalid or Indeterminate MUST be rejected".
  Demonstrated `valid: true` for restrictions `[app]` AND `[https://only-this-one.example]` with
  `audience=app`; for an `xsi:type` custom `<Condition>`; for two `<ProxyRestriction>`s (at most one is
  allowed); and with a second, expired `<Conditions>`.
  **Do:** every `AudienceRestriction` must contain the expected audience; reject unknown conditions,
  duplicate `OneTimeUse`/`ProxyRestriction`, and more than one `<Conditions>`; report `OneTimeUse` (or
  reject it unless replay protection is on — R-34).

- [ ] **R-22 · SAML: SAML Core §5 signature processing is not enforced.**
  `Medium` · security/spec-conformance · `M` · *demonstrated*
  The suite: the signature "MUST be validated as described in SAML Core, section 5". `:120` delegates
  to Keycloak's `AssertionUtil.isSignatureValid`, which does not apply §5's profile:
  - §5.4.2 "Signatures MUST contain a single `<ds:Reference>`" — two References verify;
  - §5.4.4: a verifier allowing other transforms "MUST ensure that no content of the SAML message is
    excluded from the signature" — an assertion signed with an XPath filter
    `not(ancestor-or-self::saml:Subject)`, whose NameID was then changed to a victim's, returned
    `valid: true, subject=…/victim` under both the JDK and Santuario providers;
  - algorithms and key sizes are whatever the XML-DSig provider and JVM policy allow — with Santuario
    registered, `rsa-sha1` and a 512-bit RSA IdP key verify; the JDK policy accepts RSA-1024;
  - SAML Core §4.1.2: a relying party "MUST NOT process any assertion with a major assertion version
    number not supported" — `Version="3.0"` verifies; `IssueInstant` in 2099 verifies; a signed Response
    whose `Issuer` differs from its assertion's verifies (Profiles §4.1.4.2 requires both to be the IdP);
    an inner assertion signature by a *different* key is ignored (Profiles §4.1.4.3 "Verify any
    signatures present").
  **Do:** validate the direct-child `ds:Signature` with JSR-105 directly (`KeySelector.singletonKeySelector`
  on the trusted key): exactly one Reference with `URI = "#" + ID`; transforms ⊆ {enveloped-signature,
  exc-c14n}; allow-listed SignatureMethod (RSA-SHA256+, RSA-PSS, ECDSA-SHA256+) and DigestMethod (SHA-256+);
  RSA ≥ 2048, EC ≥ P-256; validate every signature present; require `Version="2.0"`,
  `IssueInstant ≤ now + skew`, equal Issuers. Moving this into the provider also removes the dependency on
  Keycloak internals for the XSW defence (today the real protection is `SAML2Signature.configureIdAttribute`).

- [ ] **R-23 · Self-signed CID: CID 1.0 verification-method rules are only partly applied.**
  `Low` · spec-conformance · `S` · *demonstrated*
  CID 1.0 §2.2: a verification method "MUST include `id`, `type`, `controller`" and "MUST NOT contain
  multiple verification material properties". Accepted today: a method with no `id`, selectable by its
  JWK `kid` (§3.3 retrieves by `verificationMethod.id`); a method with both `publicKeyJwk` and
  `publicKeyMultibase`; several `type` or `controller` values (`SelfSignedCidVerifier.java:565, 578,
  674, 811-813`). `selectByKid` (`:730-757`) prefers the JWK `kid` over the method-id fragment, which
  differs from §3.4 fragment resolution when one method's JWK `kid` equals another's fragment (a false
  negative only); the comment at `SelfSignedControlledIdentifierDocument.java:182` says the opposite
  order.
  **Do:** refuse id-less methods and methods with more than one key-material property or `type`/
  `controller` value; match the method id (absolute, then fragment) before the JWK `kid`; fix the comment.

- [ ] **R-24 · JWS validation per RFC 7515 §5.2 / RFC 7518 §3.4: two strictness gaps.**
  `Low` · spec-conformance · `S` · *demonstrated*
  - `JwsChecks.criticalHeaders` (`:47-76`) decodes the header with the strict JDK decoder and reports
    "no `crit`" when that fails, while Keycloak's `Base64Url.decode` truncates at `=` and maps `+`/`/`. A
    signed header carrying `crit: ["urn:x"]` encoded with a trailing `=junk` returned `valid: true` with
    `noUnsupportedCriticalHeaders: true`. §5.2 step 2: decode "following the restriction that no line
    breaks, whitespace, or other additional characters have been used"; on failure the JWS "MUST be
    rejected". (Only the signer can produce this, so it is a conformance gap, not an exploit.)
  - Keycloak's ECDSA verifier converts R‖S to DER by copying the first `len` bytes and ignoring the rest,
    so an 80-byte ES256 signature verifies in production while the unit-test path rejects it. RFC 7518
    §3.4: "The JWS Signature value MUST be a 64-octet sequence. If it is not … the validation has failed."
  - RFC 7519 NumericDate must be a JSON number; `exp` as a string or float is accepted.
  **Do:** require all three segments to match `[A-Za-z0-9_-]*` and fail on an undecodable header; check
  the ES\* signature length before calling the provider (both JWT suites); reject non-integer dates.

- [ ] **R-25 · SAML trust is "out of band" in the suite but supplied per request here**
  (challenges COMPLIANCE divergence 5). `Medium` · security/design · `M` · *verified*
  The suite: "there must be a trust relationship with the issuing identity provider … established
  out-of-band". `SamlResourceProvider.java:105-114` takes the certificate from the request, nothing binds
  it to the reported `<Issuer>`, and the result does not say which certificate was used. A relying party
  that tries each trusted IdP certificate in turn accepts IdP-A signing `Issuer=https://idp-b.example`
  with a B user's NameID. `valid: true` therefore means "a trust decision was made" for the OpenID and
  CID suites but "this certificate signed it" for SAML. The Recipient also cannot be bound to an expected
  value — the half of **P1-M2** that was checked off while still outstanding.
  **Do:** when no `certificate` is passed, resolve trust from the realm's SAML identity providers
  (`SAMLIdentityProviderConfig.getIdpEntityId()` matched to `<Issuer>`, then `getSigningCertificates()`,
  which also handles rotation); a setting that disables caller-supplied certificates; always report the
  certificate's SHA-256 thumbprint and the trust source; optional `expected_issuer` and
  `expected_recipient` parameters. Rewrite divergence 5 accordingly.

---

## P2 — Hardening, interoperability and SHOULD-level

- [ ] **R-26 · Cache discovery, JWKS and CID documents; stop calling ourselves over HTTP.**
  `Medium` · performance/privacy · `M` · *verified*
  Every OpenID verification makes three fetches and every HTTPS self-signed one makes one, with no cache
  (`LWSCredentialVerifier.java:262-324, 425-485`). Both suites' privacy sections: "Verifiers are
  encouraged to cache controlled identifier documents to reduce unnecessary network requests and the
  associated metadata leakage." For this realm's own tokens Keycloak makes three loopback HTTP calls while
  holding a worker thread, which also feeds R-02's shared bucket.
  **Do:** bounded, TTL-limited caches for discovery and JWKS (refresh on an unknown `kid`, rate-limited)
  and for CIDs (honour `Cache-Control`); short-circuit `iss` equal to this realm's issuer to the local key
  store and user lookup.

- [ ] **R-27 · Key selection and key strength.** `Low` · security-hardening · `S` · *verified*
  - OpenID JWKS selection (`LWSCredentialVerifier.java:456-475`) ignores `use`/`key_ops` (verifies with a
    `use: enc` key) and the JWK's `alg`; with no `kid` it tries only the first type-compatible key (breaks
    during rotation; OIDC Core §10.1 requires `kid` when the set has several keys); one unparseable key
    (`oct`, an unsupported curve) throws and aborts the whole loop; `id_token_signing_alg_values_supported`
    is not consulted (§3.1.3.7 step 7, SHOULD).
  - No RSA minimum size in either JWT suite. RFC 7518 §3.3: "A key of size 2048 bits or larger MUST be
    used with these algorithms."
  - Ed25519 (`did/DidKey.java:284-296`): the small-order identity point is accepted — with it,
    `(R = identity, S = 0)` verifies **any** message, so that `did:key` is forgeable by anyone — and a
    non-canonical `y ≥ p` encoding passes the canonical re-encode check, giving one point two `did:key`
    identifiers (RFC 8032 §5.1.3: decoding fails for `y ≥ p`). *Demonstrated against the JDK verifier.*
  **Do:** filter on `use`/`key_ops`/`alg`; try/continue per key; try all candidates when `kid` is absent;
  enforce RSA ≥ 2048; reject small-order and non-canonical Ed25519 points.

- [ ] **R-28 · Time-claim hardening.** `Low` · security-hardening · `S` · *demonstrated*
  Accepted today in both JWT suites: `iat` ten years in the future, `iat > exp`, and `exp` in 9999 (no
  lifetime bound). **P1-C1** proposed rejecting a future `iat` and a configurable maximum credential age;
  only `iat` presence was implemented. **Do:** reject `iat > now + skew` and `iat > exp`; optional
  `max-credential-lifetime-seconds` on `exp − iat`.

- [ ] **R-29 · Follow (or explicitly refuse) redirects when dereferencing a subject.**
  `Low` · interop/docs · `S` · *verified*
  Redirects are disabled outright (`OutboundHttp.java:137`, P0-6), so a WebID that answers `303 See Other`
  (the httpRange-14 pattern) or redirects http→https fails as "did not return a controlled identifier
  document". Since `GuardedDnsResolver` vets every connection, following up to three redirects with
  `SsrfGuard` re-checked per hop — keeping the original `sub` as the required `id` — is safe. **Do:**
  implement that, or list "redirects are not followed" as a divergence in `COMPLIANCE.md`.

- [ ] **R-30 · `LWSSubMapper` trusts the WebID attribute too far.** `Low` · security · `S` · *verified (first point)*
  `openid/LWSSubMapper.java:144-199`. A value pointing into this realm's own hosted namespace for a
  *different* user (`{issuer}/lws/cid/<victim-id>`) passes `isDereferenceableUrl`, and the victim's hosted
  CID then vouches for this issuer — full impersonation, prevented today only by the `ADMIN_EDIT`
  deployment policy. Also: no uniqueness check (OIDC Core §2: `sub` is "never reassigned"); no 255-ASCII
  limit; `user.getId()` concatenated without percent-encoding (custom user storage ids); separate include
  flags can make the ID Token's and userinfo's `sub` differ (OIDC Core §5.3.2 "MUST exactly match").
  **Do:** refuse values under `{issuer}/lws/cid/` other than the user's own; warn at runtime if the
  attribute is user-editable (UserProfileProvider); encode the id; enforce the limit; tie userinfo to the
  ID Token flag.

- [ ] **R-31 · SAML: a wrapped document is certified.** `Low` · security (defence in depth) · `S` · *demonstrated*
  `findSignedElement` (`SamlCredentialVerifier.java:322-335`) searches the whole document for a signed
  assertion. An unsigned Response whose direct-child Assertion is forged, with the genuine signed
  assertion moved into `<samlp:Extensions>`, returns `valid: true, subject=<genuine>`. The verifier's own
  output is right, but it vouches for a credential that a consumer re-parsing it (e.g. `lws-server`
  during an RFC 8693 exchange) would read as the forged subject. `SamlVerifierTest.signatureWrappingDefeated`
  (`:99-109`) asserts `valid: true` for a document carrying a forged sibling assertion. `verifiedAssertion` (`:289`) matches `Response` by local name only.
  **Do:** the signed assertion must be the root or a direct child of a root `samlp:Response`; reject any
  other `Assertion`/`EncryptedAssertion` anywhere; check the namespace; flip the test.

- [ ] **R-32 · SAML behaviours that are stricter than the profile, or undocumented.** `Info` · docs · `S`
  Exactly one `<SubjectConfirmation>` is required (Profiles allows several, "at least one bearer");
  `NotBefore` on `<SubjectConfirmationData>` is accepted though Profiles says it "MUST NOT" be present;
  `InResponseTo`/`Address` are ignored; `EncryptedAssertion`/`EncryptedID` and DEFLATE input are
  unsupported (fails closed, not in COMPLIANCE); `Base64.getMimeDecoder` (`:356`) silently skips
  characters outside the alphabet. **Do:** document each in COMPLIANCE, or align with the profile.

- [ ] **R-33 · The served self-signed CID can publish duplicate method ids.** `Low` · correctness · `S` · *demonstrated*
  `ssicid/cid/SelfSignedControlledIdentifierDocument.java:184-187`: the positional `#key-<n>` fallback can
  collide with a real `kid` (a JWK with `kid: "key-2"` followed by one without a `kid`), and two JWKs
  with the same `kid` collide outright; in RDF the two methods merge into one node with two
  `publicKeyJwk`, and after a Turtle round trip only one key is collected, so tokens signed with the
  other fail. **Do:** de-duplicate ids; refuse or log duplicate `kid`s.

- [ ] **R-34 · Replay protection cannot be turned on, though COMPLIANCE says it can.**
  `Low` · docs/maintainability · `S` · *verified*
  `ReplayCache` is never instantiated in `src/main`; `SsiCidResourceProvider.java:164` always uses the
  null-cache constructor; no setting enables it. `COMPLIANCE.md` lists `notReplayed` as optional and
  divergence 3 says "Opt in per caller (P2-8)". Its TTL also ignores the token's `exp`, so with a short
  window a token is replayable once the window passes. `ReplayCache.java:70` contains a raw NUL byte, so
  git treats the file as binary (`-text`), `grep` skips it and `text=auto` does not apply.
  **Do:** wire a factory-level cache to a documented setting with TTL = max(window, `exp` − now + skew),
  or delete the class and the claims; write `'\0'` as an escape either way.

- [ ] **R-35 · Configuration precedence and validation.** `Low` · correctness/config · `S` · *demonstrated*
  - A scope value is overwritten by another provider's system-property/environment fallback
    (`config/ServerSettings.java:185-217`): `lws` scope `http-timeout-millis=1000` plus
    `-Dlws.authn.http.timeoutMillis=60000` yields 60 000, contradicting "scope first"; the result depends
    on factory init order. **Do:** apply every provider's scope values first, then fall back once.
  - Bad values silently become defaults: `enabled=flase` → `true`; `rate-limit=-1` → limiting **off**;
    `http-timeout-millis=99999999999` → 5 000 rather than the clamp. **Do:** warn on every fallback, and
    treat a negative rate limit as invalid, not "off".
  - The scope key `enabled` is also Keycloak's own provider switch: with `…--lws-saml--enabled=false`
    Keycloak never loads the factory, so a realm attribute cannot re-enable it (contrary to
    `configuration.md` and `SettingsTest.aRealmAttributeOverridesTheProviderWideFlagInBothDirections`),
    the 404 is Keycloak's rather than the documented JSON shape, and server-wide settings given only to
    that provider are lost. **Do:** rename the key (e.g. `serve`) or document the interaction.
  - IPv6 allow-list entries written `[::1]`, or hosts with a trailing dot, never match (fails closed).
  - `lws.authn.http.mode` / `LWS_AUTHN_HTTP_MODE` is read outside `Settings` and is undocumented; the
    guarded client ignores JVM proxy settings, so a deployment that needs an egress proxy must fall back
    to the unguarded session client. **Do:** document it; consider explicit proxy support that keeps the
    guard.

- [ ] **R-36 · HTTP details.** `Low` · spec-conformance · `S` · *verified*
  `VerifyAccess.java:216-219` always sends `error="invalid_token"`, even when no `Authorization` header
  was sent (RFC 6750 §3.1: SHOULD NOT include an error code then), and RFC 6750 §3 forbids `"` and `\` in
  `error_description`, so a configured role name could make the header non-compliant. `429`s carry no
  `Retry-After` (`VerifyAccess.java:155-158`, `CidEndpoint.java:92-95`). The public CID `GET` has no CORS
  headers, so browser-based verifiers cannot read it — `Access-Control-Allow-Origin: *` plus
  `Access-Control-Expose-Headers: ETag` is safe for a credential-free document (leave the verify
  endpoints without CORS). `RateLimiter` uses the wall clock (`:57, 69-73`): a backwards clock step keeps
  an empty bucket empty until the clock catches up — use `System.nanoTime()`.

- [ ] **R-37 · `did:web` edge cases.** `Info` · robustness · `S` · *verified*
  `Dids.java:213-218` accepts `.`, `..` and `%2F` path segments
  (`did:web:example.com:..:..:etc` → `https://example.com/../../etc/did.json`; the `id` check prevents
  impersonation, but these should be refused), and single-label hosts such as `localhost` pass
  `isDomainName` although the method requires a fully qualified domain name.

- [ ] **R-38 · `PublicJwk` does not know AKP's private member.** `Info` · security · `S`
  `PublicJwk.PRIVATE_MEMBERS` lacks `priv` (the `AKP` key type, which Keycloak 26.7.4's `JWKParser` now
  parses), so such a key would be trimmed rather than refused, and its `pub` dropped. Add `priv`, and
  refuse unknown key types explicitly. (Also: `JwsSignatures`, used outside Keycloak, treats EdDSA as
  Ed25519 only while Keycloak also verifies Ed448; a `did:key` is decoded twice per verification.)

- [ ] **R-39 · SAML always requires an `<AudienceRestriction>`** (challenges divergence 2 from the other
  side). `Info` · docs · `S`
  With no `audience` requested, `SamlCredentialVerifier.java:243-249` still rejects an assertion with no
  restriction, although core makes audience RECOMMENDED and the SAML suite explicitly contemplates "an
  authentication credential with no audience restrictions". Defensible (Profiles §4.1.4.2 requires one
  for Web SSO), but it should be stated as a SAML-specific choice in COMPLIANCE, not covered by
  divergence 2's "optional per request".

---

## P3 — Tests, build, CI, packaging and documentation

- [ ] **R-40 · CI: the dependency-review job fails every pull request; updates are stuck.**
  `Medium` · ci · `S` · *verified (Actions API)*
  `.github/workflows/ci.yml:126-136` fails with "Dependency review is not supported on this repository.
  Please ensure that Dependency graph is enabled" on every `pull_request` run (e.g. 36915126459,
  36914930512). Dependabot PRs #3, #4, #5 and #8 sit open and red, so the SHA-pinned actions are two to
  three majors behind and runs already warn that Node.js 20 is deprecated. `ubuntu-latest` moves to
  Ubuntu 26 from 19 October 2026.
  **Do:** enable the dependency graph (and submit the resolved Maven graph with
  `maven-dependency-submission-action` — static POM parsing does not see Jena's transitive libraries) or
  make the job non-blocking until it is; merge the action updates; pin `ubuntu-24.04`; add `concurrency`
  and `timeout-minutes`; don't run both `push` and `pull_request` for the same branch.

- [ ] **R-41 · Dependabot proposes bumps that break deliberate pins.** `Low` · dependency · `S` · *verified*
  PR #3 moves `jakarta.ws.rs-api` 3.1.0 → 4.0.0 (an API Keycloak 26 does not provide); PR #4 moves JUnit to
  6.x (a separate migration, per P4-4); PR #8 moves caffeine to 3.3.0 and jspecify to 1.0.1, breaking the
  POM's "Jena's version" / "Keycloak's version" rules. **Do:** `ignore` rules for provided APIs and
  Jena-pinned versions; close #3 and #4 or schedule them deliberately.

- [ ] **R-42 · The shaded JAR bundles four libraries Keycloak also ships, unrelocated.**
  `Medium` · packaging · `S` · *verified (JAR contents)*
  | Package | In the JAR | Keycloak 26.7.4 ships |
  |---|---|---|
  | `com/google/gson` | 2.14.0 | 2.13.2 |
  | `org/apache/commons/io` | **2.20.0** — older than Jena's declared 2.22.0 *and* the server's | 2.21.0 |
  | `org/apache/commons/lang3` | 3.20.0 | 3.20.0 |
  | `com/google/errorprone` | 2.48.0 | 2.47.0 |
  The commons-io downgrade is the same nearest-wins mediation problem the POM already pins away for
  Titanium and Caffeine; it contradicts `docs/build.md`'s two-strategy table, and `banDuplicateClasses`
  cannot see it because it ignores `provided`.
  **Do:** pin and relocate (or make `provided` where the server's copy satisfies Jena); add
  `requireUpperBoundDeps`; add a CI step that fails on unrelocated `com/google/gson` or
  `org/apache/commons/{io,lang3}` entries in the JAR.

- [ ] **R-43 · The integration test skips silently without Docker; nothing proves it ran**
  (absorbs **S-15**). `Low` · ci/test · `S` · *verified*
  `LwsAuthIT.java:151-152` uses `assumeTrue(isDockerAvailable)`, so a broken Docker is 24 skipped tests
  and a green build, and failsafe reports are not uploaded — so S-15 ("run the two new tests in CI") still
  cannot be confirmed from outside, although `master` CI is green at `edda85b`. **Do:** a
  `-Dlws.authn.requireDocker` (set in CI) that fails instead of skipping, or assert `skipped=0` in
  `target/failsafe-reports`; upload the reports.

- [ ] **R-44 · Test gaps: rules with no negative test.** `Medium` · test-gap · `M` · *verified (grep)*
  A verifier that wrongly *accepts* is the silent failure mode; each rule below can be deleted today
  without a test failing.
  - **OpenID:** tampered signature (`signatureValid`); expired or missing `exp` (`notExpired`); wrong
    `typ`; CID `id` ≠ `sub`; dereference returning non-200 or an unsupported `Content-Type`;
    `serviceEndpoint` ≠ `iss` (the existing fixture only changes `type`); `azp` ≠ `client_id` with a
    correct `aud` (`authorizedPartyMatchesClient`); discovery non-200. The JSON-LD path and the compact
    fallback are never exercised for OpenID (every OpenID test serves Turtle). `LWSSubMapper` and
    `ControlledIdentifierDocument` have no unit tests.
  - **Self-signed CID (`verify()` level):** `alg: none`, `crit`, wrong `typ`; missing `exp`/`iat`/`aud`;
    future `nbf`; `verificationMethodActive: false` (only tested in the collectors); `subjectIdMatches:
    false`; `notReplayed`. `did:web` resolution has **no test at all** (non-200, wrong media type,
    non-object body, `id` mismatch); HTTPS dereference failures; ES384/ES512/RS\*/PS\* through Keycloak's
    providers in `LwsAuthIT`.
  - **SAML:** unsigned credential (`signaturePresent`); expired `NotOnOrAfter` and future `NotBefore`;
    `audienceMatched`/`audiencePresent` (every test passes the matching audience); `singleAssertion`,
    `signatureCoversSignedElement` by name; empty NameID; SubjectConfirmation count ≠ 1; missing
    `SubjectConfirmationData`; unparseable timestamps; a not-yet-valid certificate; base64 input. The
    **signed-Response branch has no test at all**, and `LwsAuthIT` sends only `<samlp:Response/>`, so no
    real signed Response ever runs through Keycloak's XML-DSig provider and JVM policy (R-22, R-09).
  - **Access control:** `VerifyAccessTest` covers only parsing; untested are secret-mode match/mismatch,
    `role` → `403 insufficient_scope`, and rate limit → `429 slow_down` without a challenge.
  - **Shared:** `JwsChecks.withinValidityWindow` and `typeIsJwtOrAbsent` have no direct tests (skew
    boundary, `nbf`, zero `exp`); no tests for slow/endless bodies, pool exhaustion, NAT64/6to4/compatible
    addresses, unrequested RDF syntaxes or nesting depth.
  - Plus a regression test for each P0/P1 item as it is fixed. `LwsAuthIT` re-implements JWT minting at
    18 sites instead of using `testsupport/SelfIssuedJwts`.

- [ ] **R-45 · The SBOM does not describe the JAR.** `Medium` · build · `S` · *verified*
  `target/bom.json` lists 208 components, all `required`; about 180 are Keycloak's `provided` tree
  (Quarkus, netty, grpc, guava, xmlsec …) plus protobuf-java, which the shade plugin excludes, and none of
  the relocations are reflected. CI archives it "so what actually shipped can be matched against an
  advisory", but scanners will attribute Keycloak's CVEs to `lws-authn`. **Do:**
  `<includeProvidedScope>false</includeProvidedScope>`, account for the shade excludes, `makeBom`.

- [ ] **R-46 · Licence files in the JAR.** `Low` · packaging · `S` · *verified*
  The Docker-built JAR carries **no licence**: `LICENSE` is outside the build context (`.dockerignore`),
  `IncludeResourceTransformer` skips a missing file silently, and the Apache transformer drops every other
  `LICENSE`. The merged `META-INF/NOTICE` reads "Copyright 2006-2026 The Apache Software Foundation" — the
  transformer's defaults, because only `projectName` is set (`pom.xml:463-465`). Dexx collections
  (MIT) ships no licence text. **Do:** `!LICENSE` in `.dockerignore` and `COPY LICENSE`; set
  `organizationName`/`inceptionYear` (or `addHeader=false`); include third-party licence texts.

- [ ] **R-47 · Docker quickstart.** `Low` · security/maintainability · `S` · *verified*
  `compose.yaml` publishes the port on all interfaces with `admin`/`admin` and a loopback SSRF allow-list
  — bind `127.0.0.1:8080:8080`. Base images are tag-only (no digest) and Dependabot has no `docker`
  ecosystem entry.

- [ ] **R-48 · Demo scripts.** `Low` · maintainability · `S` · *verified*
  Admin API calls use `curl -sS` without `--fail`, so a failed realm/client/user creation still prints
  "created…"; admin passwords and tokens appear in `curl` argv (visible to `ps`); JSON bodies are built by
  string interpolation (use `jq -n --arg`); `USERNAME` is the login name under Git Bash, so the scripts
  create that user instead of `alice`; `ssi-cid-demo.sh:120` exits in `jq` before its friendly `die`.

- [ ] **R-49 · Build hygiene.** `Low` · build · `S`
  No `project.build.outputTimestamp` (not reproducible); surefire unpinned while failsafe is 3.5.2; no
  Maven wrapper; no `dependency:analyze`; tests print a JUL "LogManager accessed before…" ERROR (set
  `java.util.logging.manager` in surefire); the manifest drops `Multi-Release: true`, so RoaringBitmap's
  `META-INF/versions/11` class is dead weight. Plugin updates: compiler 3.13.0 → 3.16.0, jar 3.4.2 →
  3.5.1, shade 3.6.0 → 3.6.2, failsafe 3.5.2 → 3.6.0, extra-enforcer-rules 1.12.0 → 1.12.1; libraries:
  testcontainers-keycloak 4.3.1 → 4.4.0, bcpkix 1.85 → 1.86 (test), commons-codec 1.22.0 → 1.22.1.

- [ ] **R-50 · Tag the 0.2.0 release** (carried forward from **S-13**). `Low` · release · `S`
  Still only `lws-authn-0.1.0` exists, locally and on `origin`; `e539362` (the 0.2.0 bump, the build
  deployed to both hellion servers) is untagged. Left for the maintainer.

- [ ] **R-51 · Documentation corrections.** `Low` · docs · `S`
  - `COMPLIANCE.md`: re-date the review to the 5 October baseline; remove or qualify the claims this
    review found overstated — `subjectIdMatches` "on *both* the RDF and the JSON-LD path" (R-18), SAML
    `NameID`/`Issuer` as core subject/issuer URIs (R-20), `notReplayed` "optional" and divergence 3's
    "opt in per caller" (R-34), divergence 2's reasoning for the self-signed suite (R-16) and for SAML
    (R-39), divergence 5 (R-25); add "redirects are not followed" (R-29) and the SAML limits (R-32).
  - Stale comments: `LWSCredentialVerifier.java:256-261` still says JSON-LD "is interpreted directly (see
    modelFromCompactJsonLd)"; `:217-220` cites pre-errata §3.1.3.7 step numbers (R-17);
    `SelfSignedControlledIdentifierDocument.java:182` (R-23); `pom.xml:382` says "bundled 1.20" (it is
    1.22.0).
  - `CHANGELOG.md` *Versioning* still says "The build now produces `lws-authn-0.2.0.jar`"; no
    Keep-a-Changelog link references.
  - `README.md` says every source file carries SPDX; `scripts/*.sh` and the workflows do not.
  - Document `LWS_AUTHN_HTTP_MODE` (R-35).

---

## Watch — upstream and blocked

- [ ] **W-1 · Bundle the DID 1.1 context** (carried forward from **S-14**). DID 1.1 is still a Candidate
  Recommendation Snapshot (5 March 2026) and `https://www.w3.org/ns/did/v1.1` still answers `300`.
  Revisit when it reaches PR/Rec; then consider reading DID documents through the JSON-LD processor
  (divergence 8).
- [ ] **W-2 · `w3c/lws-protocol#96` — Web-CID profile for agent identification** (open since March,
  updated 1 October). If merged it would define how an agent's CID is dereferenced over HTTP — media
  types, redirects, status codes — which bears directly on R-18, R-19 and R-29.
- [ ] **W-3 · `w3c/lws-protocol#152`** (an alternative claim for the LWS subject in the OIDC suite) and
  **#200** (FedCM in the OIDC suite) — either would change the OpenID verifier.
- [ ] **W-4 · `w3c/lws-protocol#256` — RFC 9728 protected-resource metadata for authorization-server
  discovery.** Storage/AS side; no change here, but `lws-server` and the walkthroughs would follow it.
- [ ] **W-5 · Keycloak 26.8.0** (1 October 2026; adds OID4VCI/OID4VP). Separate from R-14's patch
  upgrade: check the provided/relocated libraries again, as S-17 did.
- [ ] **W-6 · Re-review cadence.** The authentication suites have been stable since 21 September; the
  next likely trigger is a new Working Draft of the OpenID or SAML suites (both still at 3 August).
- [ ] **W-7 · Report an upstream inconsistency.**
  Core's authorization-server metadata example lists `urn:ietf:params:oauth:token-type:id-token`
  (hyphen); the OpenID suite, core's own token-request example and RFC 8693 use `…:id_token`. The code
  uses `id_token`, correctly. File an issue on `w3c/lws-protocol` so `lws-server` does not copy the typo.

---

## Archive — reviews of 2 to 30 September 2026

The backlog below is the previous version of this file, unchanged except that its headings are one
level deeper and its four open items point to where they are carried forward. It is kept because code
comments, tests, `CHANGELOG.md` and `COMPLIANCE.md` cite its ids (`P0-3`, `S-2`, …) for the reasoning
behind decisions. Two of its closed items are reopened in part by this review: **P1-M2**'s
`expectedRecipient` half was never done (R-25), and **P1-C1**'s future-`iat` and maximum-age
suggestions were not implemented (R-28).

### Introduction to the previous backlog (2 September 2026)

Prioritized backlog from a full code review of this repository against the **current W3C Linked Web
Storage drafts** (checked 2 September 2026) and against the normative specifications those drafts
incorporate by reference (CID 1.0, OpenID Connect Core 1.0, RFC 7515, SAML 2.0 Core, RFC 9110).

Every item names the file (and line, where useful) and states what the spec requires versus what the
code does today. Items are ordered so the highest-risk work comes first; within a priority band the
order is roughly "cheapest first".

**State of the tree at review time:** `mvn package` succeeded and `mvn test` was green (21 tests, 0
failures). Nothing below is a build breakage — these are security, conformance, robustness and
hygiene gaps.

> #### P0, P1, P2, P3, P4, P5 and P6 are done
>
> More precisely: every item those bands contained **at review time**, plus **P4-7** and **P6-8**,
> added afterwards. **One item is open: P0-10** — the live deployment still runs pre-P0 code. It is the
> highest priority item in this file and the only one with consequences outside the repository; it is
> also the only one that cannot be closed from inside the repository. **P1-C6** was checked off in the
> P1 pass without its fix being made; P3-3 finished it, and its entry now says so.
>
> `mvn clean verify` was green at 0.2.0: **144 unit tests** (21 before this work started) and **23** in
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
> #### P3 (all seven items)
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
> #### P5 (all five items)
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
> #### P6 (all eight items)
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
> #### P1 (all 19 items)
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
> #### P4 (all six items)
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
> - **`maven-jar-plugin` now sets `forceCreation`.** Shade replaces `target/lws-authn-0.2.0.jar` with
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
> #### P2 (all nine items)
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

### S — Specification update: the editor's drafts of 21 September 2026

Reviewed 22 September 2026 against `w3c/lws-protocol` at `3ddc642`. Seven commits have touched the
drafts since the 0.2.0 baseline (`602ca19`, 21 August 2026); three bear on this provider, and the rest
(ETag rules, the `lws10-index` rename, `lws:StorageResource`, straight quotes) are storage-side or
editorial. The OpenID and SAML suites did not change. Implementing S-2 properly surfaced four places
(S-6 to S-9) where the self-signed CID verifier did not follow CID 1.0 §3.3, which that suite cites
normatively for key selection; they were gaps in 0.2.0, not changes in the drafts.

**State after this band:** 190 unit tests green (from 144); `LwsAuthIT` 25 (from 23); and a local
end-to-end run against Keycloak 26.7.3 in dev mode, repeated on 26.7.4 after S-17 — 21 checks covering `did:key` for every key type,
`did:web` over HTTPS, CID 1.0 relationship, `Multikey` and revocation rules, a subject with a fragment,
and the deprecation headers
— plus the three demo scripts, all passing.

- [x] **S-1 · The `did:key` suite was discontinued** (w3c/lws-protocol#229, 18 September 2026) "in favor
  of lws10-authn-ssi-cid, which subsumes this specification by specifying a generalization of the
  mechanism described here". **Done:** the self-signed CID verifier resolves `did:key` subjects (S-2);
  the old endpoint is removed (S-16). The documentation describes three suites, and the CHANGELOG
  records the removal.

- [x] **S-2 · The self-signed CID suite "is designed to work with ... DID URIs"** (w3c/lws-protocol#233).
  `SelfSignedCidVerifier` fetched `sub` over HTTP, and `SsrfGuard` refuses any scheme but http(s), so a
  DID subject could only ever fail at `subjectDereferenced`.
  **Done:** `did/Dids.java` and `resolveDid()`. `did:key` expands locally into the did:key Method's
  document (a `Multikey`, referenced from `authentication`); `did:web` maps to its HTTPS URL per the
  method's Read operation and is fetched through `OutboundHttp`, with the method's own rules — a domain
  name, never an IP address; a port only as `%3A` — checked first. The resolved document then goes
  through exactly the validation an HTTPS subject's does. **Decision:** only these two methods; any
  other is refused by name (COMPLIANCE divergence 7). The suite mandates none, and every other method
  needs a ledger or a third-party resolver this provider would have to trust.

- [x] **S-3 · How to read a DID document.** DID 1.1 is a Candidate Recommendation; its context URL
  (`https://www.w3.org/ns/did/v1.1`) answers `300 Multiple Choices` pointing at a release candidate,
  and the DID 1.0 context does not define `Multikey` or `JsonWebKey` at all. **Decision:** DID documents
  are read with the JSON rules of the DID representation, not by the JSON-LD processor
  (divergence 8). Nothing is fetched and nothing unstable is bundled; the fields read are fixed by DID
  1.1 and CID 1.0. Revisit with S-14.

- [x] **S-4 · What to do with `/lws-ssi-did-key`.** **Decision: keep it, deprecated.** It implements the
  discontinued draft unchanged, so existing callers keep working — including credentials with no `kid`,
  which the self-signed CID suite requires. Every response carries `Deprecation: @1789689600` (RFC
  9745) and `Link: <../lws-ssi-cid/verify>; rel="successor-version"`; Keycloak logs a warning at
  startup; `enabled=false` on the provider turns it off. **Superseded by S-16:** the endpoint was
  removed instead.

- [x] **S-5 · Core added `subject_identifier_types_supported`** to LWS authorization server metadata
  (w3c/lws-protocol#227). **Not applicable:** `lws-authn` is not an authorization server and publishes
  no metadata (divergence 9). **Carried to `lws-server`**, which should advertise
  `["https", "did:key", "did:web"]` once it accepts what this verifier does.

- [x] **S-6 · Keys not named by `authentication` were usable to authenticate.** Both collectors accepted
  any method defined under `verificationMethod` (the RDF query matched `sec:verificationMethod` as if it
  were a relationship), and the compact reader skipped `authentication` *references*, which only worked
  because of the first bug. CID 1.0 §2.3: "Verification methods that are not associated with a
  particular verification relationship cannot be used for that verification relationship"; §3.3 requires
  the association "either by reference (URL) or by value (object)". **Done:** only
  `sec:authenticationMethod` counts in RDF; the compact reader resolves references within the document
  (§3.4) and never follows one elsewhere. Stricter — see CHANGELOG.

- [x] **S-7 · `Multikey` was not supported**, although CID 1.0 defines exactly two method types and it is
  one of them — and the one a `did:key` document uses. **Done:** decoded by the did:key codec (moved to
  `did/DidKey`, since two suites now use it), which refuses a secret-key header by name (§2.2.2); the
  derived JWK is pinned to the key type's one JWS algorithm.

- [x] **S-8 · `revoked` and `expires` were ignored.** CID 1.0 §2.2: a revoked method "MUST NOT be used".
  **Done:** new check `verificationMethodActive`; an unreadable date makes the method unusable.

- [x] **S-9 · Two smaller §3.3 / §2.2.3 gaps.** A method whose `id` names a different document was
  accepted from this one; and a `publicKeyJwk` carrying private members — which P0-1 refused to
  *publish* — was still used to *verify*. **Done:** both make the method unusable.

- [x] **S-10 · A `kid` that is the method's full identifier did not match.** The usual `kid` for a DID is
  `did:key:z…#z…`, the verification method identifier §3.3 retrieves by. **Done:** an exact match on
  the (absolute) method id comes first; `#fragment` is accepted too. A `kid` naming another document
  matches nothing, by construction.

- [x] **S-11 · `ES*` was not pinned to its curve.** `JwsChecks.algMatchesKey` checked the key family
  only, and a JCA verifier accepts, e.g., a SHA-512 signature from a P-256 key. RFC 7518 §3.4 makes
  each `ES*` one curve. **Done**, for every JWT suite; `JwsChecksTest` had asserted the looser rule
  (`ES512` with a P-256 key) and now asserts RFC 7518's.

- [x] **S-12 · A build of this tree would have been named like the 0.2.0 release.** **Done:** the POM is
  `0.3.0-SNAPSHOT`; `LwsAuthIT` takes the JAR path from Failsafe and CI uploads `target/lws-authn-*.jar`,
  so the next release bump touches neither.

- [x] **S-17 · Keycloak 26.7.3 → 26.7.4** (16 September 2026; six CVEs). **Done:** `keycloak.version`,
  the docs, and `LwsAuthIT`, whose image now comes from the POM through Failsafe. Checked, as the POM
  asks on every Keycloak upgrade: the libraries the provider marks `provided` (slf4j, jspecify) or
  relocates (titanium-json-ld, caffeine, commons-collections4, commons-codec) are the same versions in
  both distributions. The check also showed the POM's account of those libraries was wrong: S-18.

- [x] **S-18 · The POM misdescribed what Keycloak ships, and pinned commons-codec below Jena.** Its
  comments said Keycloak ships commons-codec 1.11 and commons-collections4 4.4. Those are what
  Keycloak's POMs declare, and so what Maven's mediation sees. The server bundles 1.21.0 and 4.5.0.
  Checking that turned up a real problem: Jena 6.2.0's `jena-base` declares commons-codec **1.22.0**,
  but the POM pinned 1.20.0. The pin that exists to stop Maven downgrading Jena's dependencies was
  downgrading this one. **Done:** `commons-codec.version` 1.22.0, as a property beside the other
  pins, and the shade plugin's comment now tabulates Jena's version, Keycloak's POM version and the
  26.7.4 server's version for all four relocated libraries. The rationale for relocating is restated:
  titanium-json-ld and caffeine really are older on the server; for the other two, relocation keeps
  the provider independent of what a Keycloak release ships. `README.md` § *Build* matches.

- [x] **S-16 · Decide when to remove `/lws-ssi-did-key`.** No `Sunset` is set. Removing it is a breaking
  change for any caller still minting `kid`-less `did:key` credentials. **Done:** removed, with its
  provider id and settings, before any release carried the deprecation (`799048f`). A caller gets `404`
  there and sends the same credential, with a `kid`, to `/lws-ssi-cid/verify`; the CHANGELOG's
  *Removed* entry and upgrade note say so. `LwsAuthIT.theDiscontinuedDidKeyEndpointIsGone` checks the
  `404`; like S-15's tests, it was written where there is no Docker.

- [ ] **S-13 · *(Carried forward as **R-50**.)* Tag the 0.2.0 release.** *Versioning* in `CHANGELOG.md` says to tag each release commit
  `lws-authn-<version>`; `e539362` (the 0.2.0 bump, the build deployed to both hellion servers) has no
  tag. Left for the maintainer.

- [ ] **S-14 · *(Carried forward as **W-1**.)* Bundle the DID 1.1 context** once it is published at a stable URL, and consider reading DID
  documents through the JSON-LD processor like HTTPS subjects' documents (S-3).

- [ ] **S-15 · *(Carried forward as **R-43**.)* Run the two new `LwsAuthIT` tests.** They were written where there is no Docker, so they
  compile and their behaviour was exercised by the local end-to-end run, but CI is the first place they
  will run as written.

---

### Specification baseline

| Document | Latest published version | Editor's Draft |
|---|---|---|
| Linked Web Storage Protocol 1.0 (core) | **W3C Working Draft 21 August 2026** — `TR/2026/WD-lws10-core-20260821/` | `w3c.github.io/lws-protocol/lws10-core/` — reviewed at 21 September 2026 (band S) |
| LWS 1.0 Authn Suite: Self-signed Identity (Controlled Identifiers) | **W3C Working Draft 21 August 2026** — `TR/2026/WD-lws10-authn-ssi-cid-20260821/` | `w3c.github.io/lws-protocol/lws10-authn-ssi-cid/` — reviewed at 21 September 2026: DID subjects (S-2) |
| LWS 1.0 Authn Suite: OpenID Connect | W3C Working Draft 3 August 2026 — `TR/2026/WD-lws10-authn-openid-20260803/` | `w3c.github.io/lws-protocol/lws10-authn-openid/` |
| LWS 1.0 Authn Suite: SAML 2.0 | W3C Working Draft 3 August 2026 — `TR/2026/WD-lws10-authn-saml-20260803/` | `w3c.github.io/lws-protocol/lws10-authn-saml/` |
| LWS 1.0 Authn Suite: Self-signed Identity using `did:key` | W3C Working Draft 3 August 2026 — `TR/2026/WD-lws10-authn-ssi-did-key-20260803/` | **Discontinued 18 September 2026** (S-1) |
| Linked Web Storage Vocabulary | Group Note draft, 2026-08-21 | `w3c.github.io/lws-protocol/lws10-vocab/` |
| Controlled Identifiers (CID) 1.0 | **W3C Recommendation, 15 May 2025** | — |
| Decentralized Identifiers (DIDs) 1.1 | W3C Candidate Recommendation Snapshot, 5 March 2026 | cited by the self-signed CID suite (S-2) |
| The did:key Method | W3C CCG report, v0.9 | — |
| did:web Method Specification | W3C CCG report | — |

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

### P0 — Security (fix before exposing `/verify` on the public internet)

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

- [ ] **P0-10 · *(Carried forward as **R-15**.)* The live deployment is still running pre-P0 code, and the upgrade is breaking.**
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

### P1 — Specification conformance: MUST-level gaps

#### Cross-cutting (LWS core §4.1 / §4.3)

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

#### OpenID Connect suite

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

#### Self-signed CID suite *(the 21 August 2026 draft)*

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

#### Self-signed `did:key` suite

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

#### SAML 2.0 suite

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

### P2 — Specification conformance: SHOULD-level, interop and privacy

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

### P3 — Correctness and robustness

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

### P4 — Packaging and build

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

- [x] **P4-7 · No `.gitattributes`, so line endings are whatever each clone decides — and the shell
  scripts break on Linux.** *(Added after the P4 pass, from a Windows-specific review.)*
  Git for Windows sets `core.autocrlf=true` at system level (neither local nor global config chooses
  it). Git *stores* `scripts/*.sh` with LF, so the repository content was already correct and Linux CI
  unaffected — but a Windows working tree had CRLF, including the scripts, and with no `.gitattributes`
  the outcome depended on each contributor's setting, so someone with `input` or `false` could commit
  CRLF *into* the repository and break Linux CI for everyone.

  **Done.** `.gitattributes` at the root:
  - `* text=auto` — normalises every text file to LF **in the repository**, whatever the local setting
    says. Working trees still get the platform convention, which is what a Windows editor expects.
  - `*.sh text eol=lf` — LF in the *working tree* too, on every platform.

  `git add --renormalize .` reported **no changes**, confirming the stored content was already LF; the
  three scripts were re-checked-out to pick up `eol=lf` and are now LF locally as well. The file itself
  carries the reasoning, so the next person does not have to rediscover why `eol=lf` is there.

  **Verified in a Linux container, both directions**, since the whole point is a failure invisible from
  Windows (Git Bash runs a CRLF script happily, and `bash -n` passes it):

  | Working-tree form | `./scripts/lws-demo.sh` under `debian:stable-slim` |
  |---|---|
  | LF (after this change) | runs; reaches the script's own `curl is required` check |
  | CRLF (before) | `env: 'bash
': No such file or directory`, exit 127 |

---

### P5 — Tests and CI

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

### P6 — Documentation

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
    defaults themselves changed. It also recorded that `pom.xml` still read `0.1.0` while the
    `lws-authn-0.1.0` tag pointed at the first commit, so the JAR this tree built was *named* 0.1.0
    without being 0.1.0 — harmless with one consumer, a trap the moment two builds exist on one
    machine. **That is now fixed: the version is `0.2.0`.**

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
