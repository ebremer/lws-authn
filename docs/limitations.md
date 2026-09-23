---
title: Notes and limitations
parent: Reference
nav_order: 4
---

# Notes and limitations

- **Key/identity hosting.** The OpenID and self-signed-CID `cid/{userId}` endpoints serve
  Keycloak-hosted identifiers; private keys never reach Keycloak (only public JWKs are registered). The
  SAML suite hosts nothing, and neither do DID subjects.
- **SAML trust is out-of-band.** The verifier requires the trusted IdP certificate as input; it
  validates the XML signature, the `<Conditions>` window (±60 s skew by default, `clock-skew-seconds`)
  and the audience, but does not fetch metadata or build a trust chain.
- **DID methods and key types.** `did:key` and `did:web` are resolved; other methods are refused.
  Ed25519, P-256, P-384 and P-521 are supported for `did:key` and `Multikey`; secp256k1 (which the JDK
  cannot do without BouncyCastle), BLS12-381, SM2 and RSA are not. No BouncyCastle is used, so this
  works under both default and FIPS Keycloak crypto. Curve parameters come from the JDK rather than
  being transcribed here, so the set is one table row per curve.
- **DID documents are read as JSON, not JSON-LD.** DID 1.1 is a Candidate Recommendation and its
  context is not yet published at a stable URL, so there is no definition to bundle; the structure the
  verifier relies on is fixed by DID 1.1 and CID 1.0 either way. HTTPS subjects' documents are still
  processed as JSON-LD with the bundled CID context.
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
