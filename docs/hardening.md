---
title: Security hardening
parent: Reference
nav_order: 3
---

# Security hardening

The verifiers are hardened against the classic attacks on credential-verification code. These
behaviours are covered by tests — `mvn test` for the unit tests, `mvn verify` for the container IT:

- **SSRF.** The OpenID and self-signed-CID verifiers dereference URLs taken from the credential
  (`sub`, `iss`, `jwks_uri`). Before each fetch,
  [`SsrfGuard`](https://github.com/ebremer/lws-authn/blob/master/src/main/java/com/ebremer/lws/authn/net/SsrfGuard.java) rejects non-`http(s)` schemes
  and any host that resolves to anything but a **globally reachable unicast address** — loopback,
  private, link-local (including the `169.254.169.254` cloud-metadata endpoint), carrier-grade NAT,
  documentation, benchmarking and reserved ranges, by the IANA special-purpose registries. IPv6 is
  allowed only within global unicast (`2000::/3`), and an IPv6 address that carries an IPv4 one —
  IPv4-mapped, NAT64 `64:ff9b::/96` (which on an IPv6-only subnet with DNS64 reaches private IPv4),
  6to4 — is judged by the IPv4 address inside it. Legitimate internal targets are opt-in via a
  comma-separated allow-list — system property `lws.authn.allowedInternalHosts` or environment
  variable `LWS_AUTHN_ALLOWED_INTERNAL_HOSTS`.
  - The check is part of **name resolution**, not a separate step before it: the guard is installed as
    the DNS resolver of the HTTP client the verifiers use, so the addresses it approves are exactly the
    addresses the connection manager connects to. There is no second lookup for a hostile name server
    to poison, which is what closes the DNS-rebinding window.
  - That client has **its own redirect following disabled**. Keycloak's shared client happens to
    disable redirects by default too (`spi-connections-http-client-default-allow-redirects`, default
    `false`), but that is a deployment setting one flag away from letting a `302` walk past the guard —
    so the verifiers do not depend on it. Dereferencing a **subject** follows up to three redirects
    itself (a WebID answering `303 See Other`, or http going to https), and every hop is a new request
    that the guard, the scheme rule and the breaker check as they check the first; the chain shares one
    deadline, and the document must still have the original subject as its `id`. Discovery, the JWK
    set and a `did:web` document are fetched with no redirects at all.
  - **https only.** Everything fetched carries or locates a key — the subject's document, the issuer's
    configuration, its JWK set — and over plain `http` anyone on the network path can swap it. So every
    fetch must be `https`, and the OpenID `iss` must be an https URL with no query or fragment (OpenID
    Connect Core §2; `jwks_uri` too, Discovery 1.0 §3). Plain `http` is accepted only to an allow-listed
    host — the one place a deployment vouches for the path, such as its own Keycloak on loopback.
  - **This realm is not fetched from itself.** A token whose `iss` is the realm the request came to,
    and a subject that is one of that realm's own `cid/{userId}` documents, are verified from the realm
    directly — its key store, and the code its endpoint renders documents with — so a server whose own
    address is internal no longer needs it on the allow-list for that. It still does for another realm
    on the same server, for a hostname other than the one the request used, and for a plain-`http`
    issuer, which `issuerWellFormed` accepts only from an allow-listed host.
  - **Documents are cached** — controlled identifier, DID, OpenID configuration and JWK set — for up to
    `http-cache-seconds` (default 300), less if the document's `Cache-Control` says so, and not at all
    under `no-store`, `no-cache` or `private`. A fresh copy is used without any network request, not even
    DNS. The cost is that a key removed from a document can still verify for up to that long, as it
    can for any verifier that caches; a JWT naming a key the cached JWK set lacks makes the verifier ask
    again, at most every 30 seconds.
  - An origin (scheme, host and port) that **cannot be reached** five times in quick succession — the
    name does not resolve, the connection is refused or times out, the TLS handshake fails — is refused
    without a fetch for ten seconds, so a dead target does not cost every caller a connect timeout.
    Nothing that depends on the *path* counts, since the path is the caller's choice: a `404`, a slow
    or oversized body or a document that does not parse says nothing about the origin, and counting
    them let any caller shut a healthy origin out. Once open, the breaker closes on schedule however
    often it is asked.
- **Bounded fetches.** A hostile server can try to hold a verifier's fetch open — trickling a byte at a
  time, or streaming without end. Each fetch has a hard **deadline** on the whole exchange
  (`http-deadline-millis`, 10 s), enforced by aborting the request, which shuts the connection whatever
  it is doing; a body is refused the moment it passes the **size cap** (`http-max-response-bytes`), or
  up front when its declared length does, and the connection is aborted rather than read to the end;
  and one caller may have at most `http-max-concurrent-per-caller` (4) fetches in flight, so a single
  caller cannot occupy the connection pool every verifier shares.
- **Who may call verify.** In the default `bearer` mode the caller must hold the realm role
  `lws-verifier` (configurable), checked against the user's current role mappings, so revoking it takes
  effect immediately. Any user of the realm — including a self-registered one — used to be enough, and
  every verify request makes this server fetch URLs the caller chose.
- **Rate limits.** Each verify endpoint admits `rate-limit` requests a minute (60) per caller address —
  an IPv6 address by its `/64` — and, in `bearer` mode, per authenticated user, which no header can
  spoof. Behind a reverse proxy the address is what the proxy forwards, so the proxy must overwrite
  `X-Forwarded-For` rather than append to it and Keycloak must trust only the proxy
  (`proxy-trusted-addresses`); see [configuration](configuration.md).
- **Bounded nesting.** Parsers that recurse once per level can be run out of stack by a document that
  nests deeply enough, and a `StackOverflowError` is not an exception any handler catches. A fetched
  Turtle or JSON-LD document may nest at most 64 levels (`RdfParsing.MAX_NESTING_DEPTH`), counted in one
  pass before it is parsed — five thousand levels of Turtle blank nodes, 120 KB, used to overflow; a SAML
  credential's elements at most 100, set on the verifier's own parser rather than left to the JDK, whose
  default on Java 21 is no limit. A `credential` longer than 256 KiB is refused with a `400`.
- **Information disclosure.** A verify response never reflects an upstream status code, a resolved
  address or a raw exception message. Rejections carry a `traceId`; the detail is in the server log at
  `DEBUG` under that id.
- **Private key material.** The self-signed-CID endpoint publishes only the public members of a
  registered JWK, and refuses to publish a value carrying private key material at all (CID 1.0: a
  `publicKeyJwk` map "MUST NOT include any members of the private information class").
- **SAML signature wrapping (XSW).** The SAML verifier reads claims **only from the one assertion**,
  located by precise direct-child navigation (never a document-wide `getElementsByTagName` an injected
  element could win): a Response must hold exactly one, so an injected assertion beside the signed one
  is refused, and one tucked anywhere else is never seen. Every signature on the Response or the
  assertion must follow SAML Core §5.4 — a single reference, to the signed element's own `ID`, and only
  the enveloped-signature and exclusive-canonicalization transforms, so no transform can leave part of
  the assertion unsigned — and is validated with the JDK's XML-DSig API against the trusted key alone,
  with an allow-list of SHA-2 algorithms and RSA-2048 / P-256 as the smallest keys.
- **XXE.** SAML XML is parsed with a locally-configured parser that **disallows DTDs** and disables
  external entities, independent of any caller/library parser configuration.
- **The `cid/{userId}` endpoints are unauthenticated, deliberately.** A controlled identifier is a URL
  other people dereference — that is what makes it an identifier rather than a local user record — and
  a verifier meets the subject there before any trust exists in either direction, so there is no
  credential it could present. What that costs is enumeration, which is bounded rather than closed: the
  identifiers are Keycloak user ids (random UUIDs, not guessable and not meaningful), every answer —
  document, `404`, `406`, `429` — is the same media type with the same body shape so nothing but the
  status distinguishes them, and a rate limit (`cid-rate-limit`, default 600/minute per caller) makes
  scraping slow. Set `serve=false` for a deployment that does not want to host identifiers at all.
- **Only the syntaxes asked for are read.** A dereferenced document is read only as one of the syntaxes
  the verifiers request — Turtle, JSON-LD, `application/cid`, N-Triples, RDF/XML — or as `application/json`. Anything else
  is rejected by name rather than handed to a parser: not only HTML or PDF, which once failed as a
  misleading Turtle syntax error, but other RDF syntaxes the underlying library *could* read. One of
  those, the binary RDF-Thrift encoding, turned an eight-byte body into a 95 MB allocation. Only a
  document declaring nothing at all falls back to Turtle, the syntax the verifiers ask for first.
