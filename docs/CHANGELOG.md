---
title: Changelog
nav_order: 6
---

# Changelog

Notable changes to `lws-authn`. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this project does not yet publish semantic versions (see *Versioning* at the end).

Item ids like **P0-3** refer to [`TODO.md`](https://github.com/ebremer/lws-authn/blob/master/TODO.md), which carries the full reasoning for each change.

---

## [Unreleased] — toward 0.3.0

Brings the provider up to the LWS editor's drafts of **21 September 2026** (`w3c/lws-protocol` at
`3ddc642`). Two changes to the drafts since 0.2.0's baseline touch this provider, and implementing the
second properly exposed four places where the self-signed CID verifier did not follow Controlled
Identifiers 1.0 §3.3, which that suite cites normatively for selecting a key.

> ### If you are upgrading an existing deployment, read this section
>
> **The `/lws-ssi-did-key` endpoint is gone** — see *Removed*. Move its callers to
> `/lws-ssi-cid/verify` first. And the self-signed CID verifier is **stricter**, so a document that used
> to verify may now fail — see *Behaviour that got stricter* below. And the JAR is now
> `lws-authn-0.3.0-SNAPSHOT.jar`: the tree is unreleased work, and the filename says so.
>
> **In `bearer` mode — the default — a caller of `/verify` now needs the realm role `lws-verifier`**
> (R-11). Create it in each realm and grant it to the service account that verifies credentials
> *before* upgrading, or every caller gets a `403`. `LWS_AUTHN_VERIFY_ROLE` names a different role;
> `LWS_AUTHN_VERIFY_ROLE=*` restores the old "any user of the realm".
>
> **Callers of `/lws-ssi-cid/verify` must pass `audience`** — the authorization server they verify for —
> unless the deployment sets `audience` (R-16); without either the endpoint answers `400`.
>
> For a server running an older build, [INSTALL §16](INSTALL.md#upgrading-a-deployment-that-predates-the-october-2026-review)
> has a step-by-step upgrade: what to check and change first, then a deploy in `public` mode followed by
> a switch back to `bearer`.

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
- **Re-reviewed against the specifications as of 28 September 2026** (`w3c/lws-protocol` at `9b03b32`):
  no normative change since `3ddc642`, so no code change. Core and the self-signed CID suite were
  published as Working Drafts on 21 September 2026 from the text reviewed here; the `did:key` suite's
  Discontinued Draft snapshot was prepared for publication on 29 September. The conformance statement's
  table of published versions was stale, and it named a 21 August vocabulary draft that was never
  published (the latest is the Group Note Draft of 14 July 2026). It is corrected.

### Security

Fixes from the review of 6 October 2026 (`TODO.md`, R-items). Each was reachable by any user of the
realm under the default `bearer` access mode, before any signature is checked.

- **Outbound fetches are bounded in total time, and an over-long body is cut off rather than drained**
  (R-01). The verifiers fetched through Keycloak's `SimpleHttp`, which bounds each read but not the
  exchange, and which — when its size cap tripped — closed the stream, making Apache HttpClient read the
  rest of the body to keep the connection. A server trickling bytes, or streaming without end, held a
  pooled connection and a worker thread for as long as it liked, and sixteen of them stopped every
  verification on the server. Fetches now go through `OutboundHttp.fetch`: a hard deadline on the whole
  exchange (`http-deadline-millis`, default 10 s) aborts the request, which shuts the socket; a body is
  refused as soon as it passes `http-max-response-bytes`, or up front when its declared length does; a
  non-`200` body is never read; and one caller may have at most `http-max-concurrent-per-caller`
  (default 4) fetches in flight, refused at once rather than queued. In `session` HTTP mode redirects
  are now also refused per request.
- **No caller can trip the circuit breaker against a healthy origin** (R-02). The breaker counted any
  non-`200`, a wrong media type or a document that did not parse — and the verifier counted the
  breaker's own refusal as one more failure, pushing the window out each time. Five credentials whose
  `sub` named a missing path on this server's own host therefore stopped every hosted-WebID
  verification for as long as anyone kept asking. The breaker now keeps its own books inside
  `OutboundHttp.fetch`, counts only failures no path can produce (unresolvable, connection refused or
  timed out, TLS handshake failed — not a pool wait, which is this server's load), keys on scheme, host
  and port rather than host alone, and once open closes on schedule.
- **Reading keys out of a hostile document costs time linear in its size** (R-03). Three things were
  quadratic, all before any signature is checked: base58 decoding of an unbounded `publicKeyMultibase`
  (250 000 characters took 18 s); the RDF key query, which returned the cross product of every value of
  every optional property and re-decoded a failing key on every row (a 36 KiB document took 271 s); and
  reference resolution, which searched the whole document again for every reference in
  `authentication` (8 000 of them took 30 s). A multibase value is now refused over 256 characters and a
  DID over 1 024; the RDF reader reads each method once, a property at a time; references resolve
  through an index built once. The DID syntax check no longer recurses once per character, which
  overflowed the stack — a `500` — on a DID of a couple of thousand characters.
- **A dereferenced document is read only in a syntax the verifiers asked for** (R-04). The check was
  "any media type Jena can read", which includes TriG, N3, TriX, RDF/JSON and the binary RDF-Thrift
  and RDF-Protobuf encodings. A subject served as `application/rdf+thrift` with an eight-byte body made
  the Thrift reader allocate 95 MB and return an empty graph without error; a few dozen at once ran the
  server out of memory. Now only Turtle, N-Triples, RDF/XML, JSON-LD and `application/json` are read,
  and anything else is refused by name.
- **An access token no longer verifies as an LWS credential** (R-05). The JWT suites accepted a `typ`
  header of `at+jwt` — RFC 9068's explicit "this is an access token" — and the OpenID verifier never
  looked at the payload's `typ`, the only thing that distinguishes a Keycloak access token (`Bearer`)
  from an ID Token (`ID`): Keycloak writes `"typ": "JWT"` in both headers. With the WebID mapper on
  access tokens, which was its default, a realm access token carried a WebID `sub`, `iss`, `azp` and
  `exp` — everything checked — so a resource server the user had handed one to could present it as the
  user's credential. `at+jwt` is now refused in both JWT suites, and the OpenID verifier rejects a
  payload `typ` other than `ID` (new check `tokenIsIdToken`; an absent claim, usual outside Keycloak,
  is still fine).
- **A revocation date in an unexpected shape no longer leaves a key usable** (R-06). CID 1.0 §2.2: a
  revoked verification method "MUST NOT be used". On the JSON path — every `did:web` document — the
  verifier looked for a string, and anything else read as "never revoked": a JSON-LD value object
  `{"@value": "2000-01-01T00:00:00Z", "@type": "xsd:dateTime"}`, two dates in an array, a number. Now a
  value object or an array of one is read as its date, `null` is no value, and every other shape makes
  the method unusable; `expires` follows the same rule.
- **Keys are fetched only over https** (R-07). The verifiers fetched a subject's document, an issuer's
  configuration and its JWK set over plain `http` as readily as `https`, so anyone on the network path
  to an `http` subject or issuer could substitute its keys and forge credentials for it. Every fetch is
  now `https` — plain `http` only to a host on `allowed-internal-hosts`, which the demos and the
  integration test use — and the OpenID verifier checks that `iss` is an Issuer Identifier as OpenID
  Connect Core §2 defines one: https, with no query or fragment (new check `issuerWellFormed`).
- **The SSRF guard admits only globally reachable addresses** (R-08). It refused loopback, private,
  link-local and a few other ranges, and let through everything it did not list: NAT64
  (`64:ff9b::a9fe:a9fe` is 169.254.169.254 on an IPv6-only subnet with DNS64), IPv4-compatible
  `::127.0.0.1`, SIIT, 6to4, Teredo, the benchmarking, documentation and reserved IPv4 ranges. IPv6 is
  now allowed only within global unicast less the IANA special-purpose blocks, an embedded IPv4 address
  is judged by itself, and IPv4 follows the IANA IPv4 special-purpose registry.
- **Deep nesting is refused rather than overflowing the stack** (R-09). The Turtle parser and the
  JSON-LD processor recurse once per level: five thousand nested Turtle blank nodes (120 KB) or five
  hundred nested JSON-LD contexts overflowed the stack, and the `StackOverflowError` escaped every
  handler as a `500` with a stack trace in the log. On Java 21, whose XML parser sets no depth limit by
  default, so did fifty thousand nested elements inside a signed SAML assertion, in the signature check.
  A fetched Turtle or JSON-LD document may now nest 64 levels, counted before parsing; the SAML parser
  sets its own limit of 100; each catches a `StackOverflowError` as a last resort. A `credential` over
  256 KiB is refused with a `400`.
- **The verify rate limit cannot be dodged by naming a new address** (R-10). It bucketed callers by the
  address Keycloak reported, and the documented nginx configuration appended to the client's own
  `X-Forwarded-For`, so a client could claim a fresh address on every request; an IPv6 caller had a
  bucket per address, and so one per address in its `/64`. In `bearer` mode each authenticated user now
  has a bucket too, which no header can change; IPv6 addresses are bucketed by `/64`; and INSTALL's
  nginx block overwrites `X-Forwarded-For`, with `proxy-trusted-addresses` set in `keycloak.conf`.
  **Existing installs following INSTALL step 12 should make the same two changes.**
- **A caller of `/verify` must hold a role, and losing it takes effect at once** (R-11). In the default
  `bearer` mode any access token of the realm was enough — a self-registered user's, or the demo
  `alice`'s — and every verify request makes this server fetch URLs the caller chose. The realm role
  `lws-verifier` is now required unless `role` names another, or is `*` to admit any user (which logs a
  warning). And a configured role was read from the caller's token, so a role taken away kept working
  until the token expired; it is now checked against the user's current role mappings, which also
  admits a holder whose token is a lightweight one carrying no role claim. The demo realm grants
  `alice` the role, and the demo scripts grant it to the user they verify as.
- **The documentation no longer tells you to configure the provider at `kc.sh build`** (R-12).
  `configuration.md` and `INSTALL.md` gave every provider option — `access`, `role`, `audience`,
  `allowed-internal-hosts` — as a `kc.sh build` flag. Keycloak keeps only build-time options from a
  build and drops the rest with one line in the build output, so an operator who followed the docs ran
  without the `role` or `audience` they had set, and nothing said so. They are now documented as
  `keycloak.conf` entries or `kc.sh start` options (or the `LWS_AUTHN_*` environment variables, which
  were always fine), and each provider logs the settings actually in force at startup, a secret only
  as `secret=(set)`. **If you set any provider option on `kc.sh build`, move it, and check the log.**
- **The demo no longer leaves a known password and a wildcard redirect on a real server** (R-13).
  INSTALL's "fast path" ran `lws-demo.sh` against the production server, which created `alice` with the
  password `alice` and a public client with `redirectUris: ["*"]` — and nothing said to remove them.
  `lws-demo.sh` and `ssi-cid-demo.sh` now refuse to run against anything but `localhost` without
  `PASSWORD`; the demo client — in the script and in `examples/lws-demo-realm.json` — allows only the
  password grant, with no browser flow and no redirect URIs or web origins; the demo realm has
  brute-force protection and says in its name that it is for development; and INSTALL generates a
  password, says to delete the realm afterwards, and lists that in the production checklist. **If you
  ran the fast path on a real server, delete the `lws-demo` realm.**

### Added

- **Controlled identifier documents without an `@context`, or served as `application/cid`, verify**
  (R-19). CID 1.0 §4.2.1 lets a document leave out `@context` and requires a consumer to supply the
  CID context; processed without one, every term was undefined and the document failed in both JWT
  suites. `application/cid`, CID 1.0 Appendix A's media type, was refused as "not an RDF syntax"; it is
  now read as JSON-LD, the verifiers ask for it and for `application/json`, and the CID endpoints serve
  it to a client that asks for it by name. The key-reading fallback for a document naming an unbundled
  context now reads `type` and `serviceEndpoint` arrays as the JSON-LD processor does, where a `type`
  array used to read as no type and only the first endpoint counted.
- **A Docker setup for trying the suites** (`Dockerfile`, `compose.yaml`). `docker compose up --build
  --wait` builds the provider from the checkout into a Keycloak 26.8.0 image and starts it with the
  `lws-demo` realm imported, so every demo script runs against it without setup. It is for
  development only. See [Run with Docker](build.md#run-with-docker).
- **`examples/lws-demo-realm.json` is ready for the self-signed CID suite.** Its user profile sets
  unmanaged attributes to `ADMIN_EDIT`, so an admin can register `lws_jwk` and the user cannot. `alice`
  has a fixed id, so her WebID is the same on every import.
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

### Removed

- **The self-signed `did:key` suite and its endpoint, `/lws-ssi-did-key/verify`.** The Working Group
  discontinued the suite on 18 September 2026, and the self-signed CID suite verifies `did:key`
  subjects itself (see *Added*), so the separate endpoint is removed rather than kept deprecated. A
  caller now gets `404` there. **Send the same credential to `/lws-ssi-cid/verify`**, with a `kid`
  naming its verification method (`<did>#<multibase>`) — the one thing the removed suite did not
  require. The `lws-ssi-did-key` provider id, and its `--spi-realm-restapi-extension--lws-ssi-did-key--*`
  settings, no longer exist.

### Behaviour that got stricter

- **`/verify` in `bearer` mode needs the realm role `lws-verifier`** (R-11) — see the box at the top.
  A realm that does not define it refuses every bearer caller with a `403`, and the server log says so
  once per realm.
- **`/lws-ssi-cid/verify` needs to know the target authorization server** (R-16). The suite says "the
  `aud` claim MUST include the target authorization server", and the verifier only checked that *some*
  audience was present unless told which one to expect — so a credential minted for one authorization
  server verified on behalf of any other, and so did `"aud": [""]`. Pass `audience` with each request,
  or set the `audience` setting; a request with neither is now a `400`, and `audienceMatched` is always
  checked. A blank audience no longer counts as present, in either JWT suite.
- **The OpenID suite requires `aud` and `iat`** (R-17), which OpenID Connect Core §2 makes REQUIRED in
  every ID Token; they were only read when the caller passed `client_id` or `audience`. Both are now
  checked before anything is fetched (`audiencePresent`, `issuedAtPresent`). Every provider known to
  this project sets both.
- **The subject's document must have the subject as its topmost `id`** (R-18), in both JWT suites. For a
  JSON document the check was "some node in the graph is the subject", which a document about somebody
  else passed by nesting `{"id": sub, …}` under `alsoKnownAs` — and in the self-signed suite that nested
  node's keys then verified the credential. Now the `id` of the topmost map is read from the JSON
  itself; Turtle, N-Triples and RDF/XML, which have no topmost map, must still describe the subject. A
  fetched document about somebody else is reported as `subjectIdMatches: false` — the self-signed suite
  used to report it as `subjectDereferenced: false`, "failed to dereference", and to report
  `subjectIdMatches: true` regardless.
- **An `iat` in the future, or after `exp`, is refused** in both JWT suites (new check
  `issuedAtConsistent`; the clock skew allowance applies). A credential "issued" ten years from now used
  to pass.

The rest are requirements of CID 1.0, which the self-signed CID suite cites for selecting the key, and
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
  `xsd:dateTimeStamp` makes the method unusable rather than silently current. In RDF, so does a value
  that is not a literal, or **two values for one property** — two expiry dates, two revocations, two
  `publicKeyJwk`s — where the reader used to take whichever the query returned first (R-03). In JSON, so
  does a value that is not one date: an array of two, a number, a node reference (R-06).
- **A `publicKeyJwk` carrying private members is not a usable verification method** (CID 1.0 §2.2.3).
  This provider already refused to *publish* one (P0-1); it now refuses to *verify* against one too.
- **`ES256`/`ES384`/`ES512` are pinned to P-256/P-384/P-521** (RFC 7518 §3.4), for every JWT suite. A
  JCA verifier accepts, say, a SHA-512 signature from a P-256 key; that is valid ECDSA and not ES512.
- **A token typed as something other than an authentication credential is refused** (R-05): a `typ`
  header of `at+jwt` in either JWT suite, and in the OpenID suite a payload `typ` other than `ID`. An
  ID Token from a provider that sets the payload `typ` to something else would now fail
  `tokenIsIdToken`; none known does.
- **Plain `http` subjects, issuers and `jwks_uri`s are refused** unless the host is on
  `allowed-internal-hosts` (R-07). A deployment that verified `http` WebIDs or a test OP on `http` must
  allow-list the host or move it to https; an `iss` with a query or fragment now fails
  `issuerWellFormed`.

### Changed

- **The WebID mapper no longer puts the WebID in the access token by default** (R-05). *Add to access
  token* now defaults to off, and a mapper whose configuration never mentions it — one created over
  the admin API with only the attribute set — is off too, where "not set" used to mean on. The demo
  realm and `lws-demo.sh` set it off explicitly. Existing mappers with the switch explicitly on keep
  it; turn it off unless something downstream needs the WebID in the access token. The ID Token and
  userinfo are unchanged.
- **Built and tested against Keycloak 26.8.0** (was 26.7.3; W-5), released 1 October 2026. **Run the
  provider on 26.8.0 or a later 26.8 release**; from 26.7 that is a minor upgrade of the server — every
  node stopped, the database migrated — so read Keycloak's migration notes first. Its security fixes
  include disabled clients no longer reaching a token's `aud` (CVE-2026-93999) and identity-provider
  mappers no longer granting admin roles by default (CVE-2026-12388). Nothing in the provider's own
  code needed to change: the APIs it uses — `HttpClientProvider.getHttpClient()`, the bearer
  authenticator, the realm-resource and protocol-mapper SPIs — are as they were. Of the libraries it
  shares with Keycloak or relocates, the server now ships commons-codec 1.22.1 (relocated, so the
  provider keeps Jena's 1.22.0), and slf4j, Parsson and jboss-logging take patch releases; the POM's
  table says so. 26.8 deprecates a client's *Full Scope Allowed* switch and warns at every token it
  issues for one that has it on, so the demo client now has it off: since R-11 the verifier role is
  read from the user, not the token, and nothing else in the demo needs roles in tokens.
- **Built and tested against Keycloak 26.7.5** on the way (R-14), released 30 September 2026 with
  fourteen security fixes, among them SAML Redirect Binding parameter pollution (CVE-2026-18217),
  CVE-2026-89298 and CVE-2026-88770. The documentation used to say the server "must match" the
  provider's `keycloak.version`, which only discouraged operators from taking patch releases; it now
  asks for the same minor. Of the libraries the provider shares with Keycloak or relocates, only
  Caffeine changed in that server distribution (3.2.3 → 3.2.4, the version the provider bundles anyway).
  A unit test now fails if the `Dockerfile` or `LwsAuthIT`'s fallback image disagrees with
  `keycloak.version`.
- **Built and tested against Keycloak 26.7.4** on the way (was 26.7.3), released 16 September 2026 with six security
  fixes, among them an unauthenticated denial of service through locale caching (CVE-2026-79651) and
  the `impersonation` role reaching a realm administrator (CVE-2026-17526). Run the provider on 26.7.4;
  its only breaking change concerns Authorization Services resource matching, which this provider does
  not use. The libraries the provider shares with Keycloak or relocates are unchanged from 26.7.3 — the
  distribution differs only in Quarkus (3.33.3.1 → 3.33.3.2) and Keycloak's own JARs — so the shading
  and `provided` decisions stand. `LwsAuthIT` now takes its container image from `keycloak.version`.
- **commons-codec is bundled at 1.22.0**, the version Jena 6.2.0 declares. The POM pinned 1.20.0, so
  the pin that exists to stop Maven downgrading Jena's dependencies was downgrading this one. Relocated,
  as before. The POM and README also now say accurately what Keycloak's POMs declare versus what the
  server ships: 26.7.4 bundles commons-codec 1.21.0 and commons-collections4 4.5.0, not the 1.11 and 4.4
  its POMs declare. The bundling decisions are unchanged.
- **Version `0.3.0-SNAPSHOT`.** The JAR is `lws-authn-0.3.0-SNAPSHOT.jar`, so a build of this tree cannot
  be mistaken for the 0.2.0 release (commit `e539362`, which is untagged — see *Versioning*).
  `LwsAuthIT` now takes the JAR's path from Failsafe and CI uploads `target/lws-authn-*.jar`, so neither
  needs editing at the next release.
- The multibase/did:key codec moved from `ssididkey` to a new `did` package, since the self-signed CID
  suite now depends on it; JDK signature verification moved to `jose.JwsSignatures`.

### Tests

179 unit tests (was 144), 24 in `LwsAuthIT` (was 23). New: DID syntax, the did:web URL mapping against
the method's own examples, did:key expansion against the did:key Method's worked example, the multibase
codec against the did:key and CID 1.0 test vectors, every CID 1.0 method rule above on both parsing
paths, and did:key credentials verified end to end through the self-signed CID suite for every supported
key type. `LwsAuthIT` gains a did:key credential through `/lws-ssi-cid` (Ed25519 exercising Keycloak's
EdDSA provider), and checks that `/lws-ssi-did-key` answers `404`; the removed suite's own tests went
with it.

### Documentation

The documentation is now a website, <https://ebremer.github.io/lws-authn/>, built from `docs/`.
`INSTALL.md`, `COMPLIANCE.md`, `CHANGELOG.md`, `SECURITY.md` and `CONTRIBUTING.md` moved into `docs/`
and are pages of it, as are the README's reference sections — build and deploy, each suite's
endpoints, configuration, hardening, limitations. The README is now a summary. Each document exists in
one place, so there is one copy of each to keep current.

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
