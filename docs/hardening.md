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
