# Conformance: `lws-authn`

**What this document is:** the conformance statement for `lws-authn` — which normative requirements
each suite enforces, which are deferred to the relying party, and what is supported. It is written for
someone integrating against this provider, who needs to know what a `"valid": true` actually asserts.

**Last reviewed:** 3 September 2026, against the drafts below and the code at that commit.

Item ids like **P0-3** refer to [`TODO.md`](TODO.md), which carries the reasoning and the history.
Where this document says a check exists, it names the field that appears in the `checks` object of the
verify response, so a claim here can be tested against a real response.

---

## Specification status

These are **W3C Working Drafts**, not Recommendations. Conformance here means "matches the published
normative requirements", not a Rec-level conformance certificate — the text can still change.

| Document | Latest published version |
|---|---|
| Linked Web Storage Protocol 1.0 (core) | W3C Working Draft **21 August 2026** |
| LWS 1.0 Authn Suite: Self-signed Identity (Controlled Identifiers) | W3C Working Draft **21 August 2026** |
| LWS 1.0 Authn Suite: OpenID Connect | W3C Working Draft 3 August 2026 |
| LWS 1.0 Authn Suite: SAML 2.0 | W3C Working Draft 3 August 2026 |
| LWS 1.0 Authn Suite: Self-signed Identity using `did:key` | W3C Working Draft 3 August 2026 |
| Linked Web Storage Vocabulary | Group Note draft, 21 August 2026 |
| Controlled Identifiers (CID) 1.0 | **W3C Recommendation, 15 May 2025** |

Also incorporated by reference and enforced here: OpenID Connect Core 1.0 §3.1.3.7, RFC 7515 (JWS),
RFC 7517 (JWK), RFC 8725 (JWT BCP), RFC 9110 (HTTP semantics), SAML 2.0 Core.

## Scope

`lws-authn` is the **identity and credential** side of LWS: an OpenID Provider, a host for controlled
identifier documents, and a verifier for each suite. It is **not** an LWS storage server — core CRUD,
notifications, search and access grants live in `lws-server`.

| Suite | Keycloak's role | Credential | How the verifier gets the key | Endpoint prefix | Token type |
|---|---|---|---|---|---|
| OpenID Connect | OP + CID host + verifier | ID Token (JWT), `sub` = WebID | OIDC Discovery on `iss`, found via the CID service | `/realms/{realm}/lws` | `…token-type:id_token` |
| Self-signed CID | CID host + verifier | self-issued JWT, `sub`==`iss`==`client_id` | `publicKeyJwk` in the subject's CID, by `kid` | `/realms/{realm}/lws-ssi-cid` | `…token-type:jwt` |
| SAML 2.0 | verifier | signed SAML 2.0 Response | out-of-band IdP certificate supplied by the caller | `/realms/{realm}/lws-saml` | `…token-type:saml2` |
| Self-signed `did:key` | verifier | self-issued JWT, `sub` = `did:key` | decoded from the identifier itself | `/realms/{realm}/lws-ssi-did-key` | `…token-type:jwt` |

SPI surface: four `RealmResourceProviderFactory` ids (`lws`, `lws-ssi-cid`, `lws-saml`,
`lws-ssi-did-key`) plus the OIDC `ProtocolMapper` `lws-webid-sub-mapper`.

---

## Core §4: what every credential must carry

Core §4.1 requires *subject* (URI), *issuer* (URI) and *client* on every credential, RECOMMENDS an
audience restriction naming the authorization server, §4.2 requires a signature, and §4.3 requires each
suite to be associated with a token type URI.

| Requirement | OpenID | SSI CID | SAML | did:key |
|---|---|---|---|---|
| subject REQUIRED | `subjectPresent` | `selfIssued` | `NameID` from the covered assertion | `subjectIsDidKey` |
| issuer REQUIRED | `issuerPresent` | `selfIssued` | `issuerPresent` | `selfIssued` |
| client REQUIRED | `clientPresent` (`azp`) | `selfIssued` (`client_id`) | `recipientPresent` | `selfIssued` (`client_id`) |
| audience restriction | `audienceMatched` | `audiencePresent` + `audienceMatched` | `audiencePresent` + `audienceMatched` | `audiencePresent` + `audienceMatched` |
| signed (§4.2) | `signatureValid` | `signatureValid` | `signatureValid` | `signatureValid` |
| token type URI (§4.3) | reported as `tokenType` on every result | | | |

Every result also reports the LWS `client` and the suite's `tokenType`, ready for an RFC 8693 exchange,
and fails closed when the client identifier is absent.

> **Note on `client`:** core §4.1 says the client identifier **SHOULD** be a URI. This provider requires
> the claim but does not require it to be a URI, because SHOULD is not MUST and Keycloak client ids are
> conventionally bare strings. See *Known divergences* below.

---

## OpenID Connect suite

**Enforced.** `alg` is never `none`; no unsupported `crit`; `typ`, when present, names a JWT;
`sub` and `iss` present; `azp` present (`clientPresent`). `sub` is dereferenced over the guarded HTTP
stack and the document must have an `id` equal to `sub` (`subjectDereferenced`, `subjectIdMatches`) —
on *both* the RDF and the JSON-LD path; the JSON-LD path used to default a missing `id` to the subject,
accepting a document that never claimed to describe it. The document must declare a
`https://www.w3.org/ns/lws#OpenIdProvider` service whose `serviceEndpoint` equals `iss`
(`openIdProviderServiceLocated`), located by parameterized SPARQL so an attacker-controlled `sub`
cannot inject. Discovery on `iss` must return a configuration whose `issuer` matches
(`issuerDiscoveryMatches`) and a `jwks_uri` (`jwksResolved`). The `alg` is pinned to the discovered key
type (`algorithmMatchesKey`) — the classic HS256-against-an-RSA-public-key confusion. Signature
(`signatureValid`) and an explicit `exp` (`notExpired`; a missing `exp` is not "never expires").

**Enforced when the caller asks.** OpenID Connect Core §3.1.3.7 steps 3–5, which the suite
incorporates by reference: pass `client_id` and `aud` must list it (`audienceContainsClient`) and `azp`
must equal it (`authorizedPartyMatchesClient`); pass `audience` and the credential must be restricted
to it (`audienceMatched`).

**Deferred to the relying party — read this.** Without `client_id`/`audience` the credential is fully
validated but **nothing binds it to you**: a token minted for a different relying party by the same
issuer will pass. Supply them wherever the result is treated as an authentication, or set the
deployment-wide `audience` so a caller that forgets cannot silently accept one. Restrict audiences at
issuance too (Resource Indicators, RFC 8707).

## Self-signed Controlled Identifier suite

**Enforced.** `alg` never `none`; no unsupported `crit`; `typ` names a JWT if present;
`sub == iss == client_id` (`selfIssued`); a `kid` is present (`keyIdPresent`) — no fallback to "the
only key", because the credential says which key signed it. `sub` is dereferenced and the document's
`id` must equal it. A verification method is selected by `kid` and is usable only if it is a
`JsonWebKey` the subject **controls** (`verificationMethodFound`), published for signing and consistent
with the token's algorithm (`verificationMethodUsableForSigning`, `algorithmMatchesKey`). Signature
(`signatureValid`), explicit `exp` (`notExpired`), required `iat` (`issuedAtPresent`), and an audience
that is present and — when one is configured or supplied — matched (`audiencePresent`,
`audienceMatched`).

**Optional.** `notReplayed`: a bounded `jti` cache, off by default. No suite mandates replay
protection, and refusing a second look at a live credential is only correct for a caller that treats
one verification as one use.

**Hosting.** `GET …/lws-ssi-cid/cid/{userId}` publishes each registered public JWK as an
`authentication` verification method. Only public members are ever served — a value carrying private
key material is refused outright and logged, never trimmed and published. Every method carries the
`id` CID 1.0 requires, with the `kid` percent-encoded into the fragment.

## SAML 2.0 suite

**Enforced.** The IdP certificate's own validity window (`certificateValid`; overridable only by an
explicit `allowExpiredCertificate`, for offline analysis, never a live decision).
`<samlp:Status>` must be Success (`statusSuccess`). A signature must be present and valid
(`signaturePresent`, `signatureValid`) and must **reference the signed element by its own `ID`**
(`signatureCoversSignedElement`); a signed Response must contain exactly one assertion
(`singleAssertion`). Claims are read **only from the cryptographically covered assertion**, located by
precise direct-child navigation rather than a document-wide search an injected element could win — the
signature-wrapping (XSW) defence. `<Issuer>` required (`issuerPresent`). The bearer
`<SubjectConfirmationData>` is checked for method, `Recipient` and `NotOnOrAfter`
(`bearerSubjectConfirmation`, `recipientPresent`, `subjectConfirmationWithinWindow`). `<Conditions>`
window with clock skew (`withinValidityWindow`), and audience (`audiencePresent`, `audienceMatched`).
XML is parsed with DTDs **disallowed** and external entities disabled, independent of any caller or
library configuration.

**Deferred to the relying party — read this.** SAML trust is out of band, so **the caller supplies the
certificate**. This endpoint answers *"is this Response signed by the certificate you gave me"*, not
*"does this deployment trust that IdP"*. Anyone can therefore obtain `"valid": true` for an assertion
they signed themselves with a certificate they also supplied. That is the API behaving correctly.
**Pin the expected certificate on your side**; do not treat this endpoint as a trust decision.

## Self-signed `did:key` suite

**Enforced.** `alg` never `none`; no unsupported `crit`; `typ` names a JWT if present;
`sub == iss == client_id` (`selfIssued`) and `sub` is a `did:key` (`subjectIsDidKey`). The public key
is decoded from the identifier with **no network access** (`keyDecodedFromDid`), and the identifier
must be **canonically encoded** — the decoded key is re-encoded and must reproduce it, so one key
cannot have two identifiers. `alg` pinned to the key type (`algorithmMatchesKey`), signature
(`signatureValid`), explicit `exp` (`notExpired`), required `iat` (`issuedAtPresent`), audience
present and matched. `notReplayed` optional, as above.

**Supported key types:** Ed25519, P-256, P-384, P-521. Curve parameters come from the JDK rather than
being transcribed, so the set is one table row per curve. **Not supported:** secp256k1 (the JDK cannot
without BouncyCastle) and RSA. No BouncyCastle is used at runtime, so this works under both default and
FIPS Keycloak crypto.

---

## Supported formats

**RDF syntaxes**, both served and parsed: JSON-LD (`application/ld+json`), Turtle (`text/turtle`),
N-Triples (`application/n-triples`), RDF/XML (`application/rdf+xml`). Verifiers request Turtle first.

JSON-LD is processed by Jena's **JSON-LD 1.1 reader**, so a conforming document verifies whatever shape
it is written in — aliased terms, an `@graph` wrapper, referenced rather than embedded verification
methods, additional contexts. **Contexts are resolved from copies bundled in the JAR and never
fetched**: a processor left to itself would request every `@context` URL a credential's document names,
which is an unvetted outbound fetch during verification and a dependency on `w3.org` being reachable
for anything to verify at all. A document naming a context this provider does not bundle is refused as
unverifiable rather than guessed at, with a key-reading fallback for the standardized compact shape.

A document declaring a content type that is not an RDF syntax is **refused by name**, not handed to the
Turtle parser.

**Signature algorithms:** whatever Keycloak's `SignatureProvider` offers for the JWT suites (RS*, PS*,
ES256/384/512, EdDSA), constrained by the published key; `SHA256withRSA` and the JDK's EdDSA/ECDSA for
`did:key`. `alg: none` is refused everywhere.

---

## Known divergences and deliberate choices

Each is a decision, not an oversight; each names where the reasoning lives.

| # | Divergence | Why |
|---|---|---|
| 1 | The LWS `client` identifier is required but **not required to be a URI** | Core §4.1 says SHOULD, not MUST. The bundled demo realm uses `lws-app`, a bare id, which is what Keycloak conventionally issues — see **P6-8**, and use a URI in production if your relying party cares. |
| 2 | **Audience binding is optional per request** | The suites RECOMMEND an audience restriction; enforcing one unconditionally would reject conforming credentials. A deployment that wants it mandatory sets the `audience` configuration, which applies when a request names none (**P3-6**). |
| 3 | **Replay protection is off by default** | No suite mandates it, and a verify endpoint is legitimately asked about the same live credential repeatedly. Opt in per caller (**P2-8**). |
| 4 | **`cid/{userId}` is unauthenticated** | A controlled identifier is a URL others dereference; an identity document requiring a credential would not be dereferenceable. Enumeration is bounded — random-UUID ids, a uniform response shape, and a rate limit — not closed (**P3-7**). |
| 5 | **The SAML verifier trusts the caller's certificate** | The suite's own model: SAML trust is out of band. See the suite section above. |
| 6 | **Fetch happens before the signature is known good** | Required by the specification's cold-trust algorithm and unavoidable. The exposure is addressed instead: authenticated endpoints, rate limiting, SSRF vetting at resolution time, bounded timeouts and response size, and a per-host circuit breaker (**P0-3**, **P0-5**). |

## Security posture

The residual issues that appeared in this document's July 2026 revision — DNS-rebinding SSRF,
internal-address leakage in client-facing errors, unauthenticated verify as an amplification vector,
user-writable WebID attributes, no `jti` cache — have been closed or given an explicit control; see
`CHANGELOG.md` and the P0–P3 bands of `TODO.md`. `README.md` § *Security* describes each mechanism, and
`SECURITY.md` says what is in scope for a vulnerability report and what is deliberate.

The one that is a **deployment** responsibility rather than a code one: the realm's unmanaged attribute
policy must be `ADMIN_EDIT`, not `ENABLED`. A user who can write their own `lws_jwk` or WebID attribute
can mint credentials for an identity they should not control. `INSTALL.md` step 9f.

## Verification

`mvn clean verify` — 144 unit tests plus 23 in `LwsAuthIT` against a real Keycloak 26.7.3 container.
Roughly half the integration tests assert a *rejection*, including a full third-party OpenID Provider
fixture broken one document at a time, because a verifier that wrongly rejects gets reported by its
users and one that wrongly accepts does not.

## Relationship to `lws-server`

```text
                    lws-authn (Keycloak)                 lws-server (storage)
OpenID              issues ID Token (sub = WebID)        accepts / validates ID Token
                    hosts CID + OpenIdProvider           CID trust + discovery + JWKS
                    POST /lws/verify

SSI CID             hosts CID + keys                     accepts self-issued JWT
                    POST /lws-ssi-cid/verify             dereferences CID by kid

SAML                verify utility                       accepts if IdP certs configured

did:key             POST /lws-ssi-did-key/verify         accepts self-issued did:key JWT
```

Neither alone is the full LWS product. For credential fidelity specifically, `lws-authn` is the
stricter of the two.
