# LWS Protocol Compliance: lws-authn

**Date:** 2026-07-09  
**Scope:** Whether `lws-authn` correctly implements the four W3C LWS authentication suites (aside from known security bugs).  
**Related:** code review findings (summarized under *Residual issues* below)

## Short answer

**Yes** — aside from the known security bugs and a few claim-level gaps, `lws-authn` correctly implements **all four LWS 1.0 authentication suites** as a Keycloak 26 provider: OpenID Connect, Self-signed Controlled Identifier (SSI CID), SAML 2.0, and Self-signed `did:key`. It is **not** an LWS storage server (that is `lws-server`); it is the **identity / credential** side of the ecosystem—OP/IdP support, CID hosting where required, and suite verifiers.

The suite documents are still **unofficial proposals**, so “correct” means matching the published **MUST** validation algorithms and data models, not a frozen Rec conformance certificate.

---

## What this project implements

From the [LWS protocol set](https://w3c.github.io/lws-protocol/):

| Spec | Role in `lws-authn` |
|------|---------------------|
| **authn-openid** | Keycloak as OpenID Provider; WebID `sub` mapper; hosted CID with `OpenIdProvider` service; credential verifier |
| **authn-ssi-cid** | Hosted CID with `publicKeyJwk` authentication methods; self-issued JWT verifier |
| **authn-saml** | Verifier for signed SAML 2.0 Response/Assertion with **out-of-band** IdP certificate |
| **authn-ssi-did-key** | Verifier for self-issued JWT whose subject is a `did:key` (key decoded from the identifier) |

**Not in scope for this repo** (by design): LWS Core storage CRUD, notifications, search/type index, access grants. Those live in `lws-server`.

| Suite | Keycloak role | Credential | How the verifier gets the key | Endpoint prefix |
|-------|---------------|------------|-------------------------------|-----------------|
| OpenID Connect | OP + CID host + verifier | ID Token JWT; `sub` = WebID | OIDC Discovery on `iss` (via CID service) | `/realms/{realm}/lws` |
| Self-signed CID | CID host + verifier | Self-issued JWT; `sub==iss==client_id` | `publicKeyJwk` in subject CID by `kid` | `/realms/{realm}/lws-ssi-cid` |
| SAML 2.0 | Verifier (+ optional IdP use of Keycloak SAML) | Signed SAML 2.0 | Out-of-band IdP certificate | `/realms/{realm}/lws-saml` |
| Self-signed `did:key` | Verifier only | Self-issued JWT; `sub` = `did:key` | Decoded from the `did:key` itself | `/realms/{realm}/lws-ssi-did-key` |

SPI surface: four `RealmResourceProviderFactory` ids (`lws`, `lws-ssi-cid`, `lws-saml`, `lws-ssi-did-key`) + OIDC `ProtocolMapper` (`lws-webid-sub-mapper`). META-INF/services registration is complete.

---

## OpenID Connect suite — yes (core algorithm)

Spec: [lws10-authn-openid](https://w3c.github.io/lws-protocol/lws10-authn-openid/)

### Present and aligned

| Requirement | Implementation |
|-------------|----------------|
| ID Token MUST NOT use `alg: none` | Enforced in `LWSCredentialVerifier` |
| `sub` / `iss` for subject and issuer | Required; fail if missing |
| Trust via CID: dereference `sub` | `OutboundHttp` + `SsrfGuard`; RDF/JSON-LD parse |
| Service type `lws:OpenIdProvider` with `serviceEndpoint == iss` | SPARQL ASK (parameterized) / compact JSON-LD path |
| OIDC Discovery + JWKS + signature | Discovery issuer match, JWKS by `kid`/`alg`, Keycloak `SignatureProvider` |
| Algorithm–key pinning (hardening) | `algMatchesKey` (blocks HS* confusion against OP public keys) |
| Expiry | Explicit `exp` required; `isActive()` window |
| Issuance: `sub` as WebID | `LWSSubMapper` (hosted CID or attribute) |
| Hosted CID with OpenIdProvider service | `GET …/lws/cid/{userId}` content-negotiated |
| Token type URI `…token-type:id_token` | Documented / constants |

### Gaps / softness

| Gap | Nature |
|-----|--------|
| Serialization MUST use **`azp`** as LWS client id | Not required on verify |
| **`aud`** | Intentionally not validated (documented; left to RP / resource indicators / token exchange) |
| Full OIDC Core §3.1.3.7 | Partial (sig + iss + exp; not full RP audience binding) |
| CID `id` equals `sub` | Weaker on compact JSON-LD path than ideal |
| Fetch-before-signature | Spec-required for cold trust; enables SSRF/DoS residual (see review) |

**Verdict:** Trust chain and validation shape match the suite. Audience/`azp` are the main intentional or incomplete claim pieces.

---

## Self-signed Controlled Identifier — yes (core algorithm)

Spec: [lws10-authn-ssi-cid](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/)

### Present and aligned

| Requirement | Implementation |
|-------------|----------------|
| `alg` MUST NOT be `none` | Enforced |
| `sub == iss == client_id` | Enforced |
| Dereference `sub` to CID | Same outbound stack as OpenID |
| Select verification method by JWT `kid` | `selectByKid` over `authentication` / `verificationMethod` / RDF |
| Validate signature (RFC 7515) | Keycloak `SignatureProvider` + JWK |
| Require `exp` | Explicit (not “missing exp = never expires”) |
| Require `aud` present | Enforced (presence; not a configured AS match) |
| Hosted CID with `publicKeyJwk` | `SsiCidResourceProvider` + document builder |
| Token type `…token-type:jwt` | Documented / constants |

### Gaps / softness

| Gap | Nature |
|-----|--------|
| Serialization **`iat` MUST** | Not hard-required |
| **`aud` MUST include the target AS** | Presence only; no expected-audience param like SAML |
| CID **`id` equals `sub`** | Not asserted as clearly as on `lws-server` SSI path |
| `algMatchesKey` pin | OpenID has it; SSI CID lacks the same explicit pin (fail-closed in practice today via Keycloak) |
| Compact JSON-LD without full expansion | Spec-shaped docs work; exotic contexts may fail interop |

**Verdict:** Core self-issued JWT + CID key selection algorithm is correct and close to the suite text.

---

## SAML 2.0 suite — yes (protocol model); strong verifier hardening

Spec: [lws10-authn-saml](https://w3c.github.io/lws-protocol/lws10-authn-saml/)

### Present and aligned

| Requirement | Implementation |
|-------------|----------------|
| Credential MUST be signed | Signature required on Response or Assertion |
| Trust out of band | Caller supplies IdP PEM certificate (suite model) |
| Validate signature (SAML Core §5) | Keycloak `AssertionUtil` + local checks |
| `NameID` → subject | Read only from cryptographically covered assertion |
| `Issuer` → issuer | From verified assertion |
| `Recipient` → client | Extracted from `SubjectConfirmationData` when present |
| Audience | Required present, or match optional expected audience |
| Validity window | Requires `NotOnOrAfter`; clock skew; unparseable → reject |
| XXE hardening | DTD disallowed, secure processing, no external entities |
| Signature wrapping (XSW) | Ref must cover signed element ID; single assertion under signed Response; claims only from covered tree |
| Token type `…token-type:saml2` | Documented / constants |

### Gaps / softness

| Gap | Nature |
|-----|--------|
| **Caller-supplied trust material** | Any caller can get `valid: true` for a self-signed assertion + matching cert — correct as a crypto utility, dangerous if misread as “this Keycloak deployment attested the IdP” |
| Spec validation section is thin | Implementation is **stricter** than the minimum MUST text (good) |
| Recipient not always required | Extracted; suite serialization says MUST for tokens; validation section does not force it |

**Verdict:** Protocol model (OOB trust + signature + NameID mapping) is correct. Operational footgun is trust semantics of the public verify API, not missing SAML steps.

---

## Self-signed `did:key` — yes (core algorithm; cleanest suite)

Spec: [lws10-authn-ssi-did-key](https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/)

### Present and aligned

| Requirement | Implementation |
|-------------|----------------|
| `alg` MUST NOT be `none` | Enforced |
| `sub` MUST be `did:key:` | Enforced |
| `sub == iss == client_id` | Enforced |
| Decode public key from identifier (no network) | `DidKey` multibase + multicodec (Ed25519, P-256) |
| Validate JWT signature | Pure JDK (EdDSA / ES256 P1363) |
| Require `exp` | Explicit |
| Require `aud` | Presence required |
| Pin JWT `alg` to key type | Enforced |
| Token type `…token-type:jwt` | Documented / constants |

### Gaps / softness

| Gap | Nature |
|-----|--------|
| Serialization **`iat` MUST** | Not hard-required |
| **`aud` MUST include the target AS** | Presence only |
| Full multicodec zoo | Practical subset (Ed25519 / P-256), not every codec |

**Verdict:** Closest suite to a complete, self-contained implementation of the draft.

---

## Cross-cutting protocol quality

### Strengths

- Fail-closed verifiers (early fail, broad catch → invalid).
- Parameterized SPARQL for attacker-controlled IRIs (injection regression tested).
- SSRF baseline for CID/discovery/JWKS (`SsrfGuard` + timeouts + body size cap).
- OpenID algorithm–key pinning and did:key alg pin.
- SAML XXE + XSW defenses with unit tests.
- Packaging: Jena shaded/relocated for Keycloak classpath safety.
- IT smoke against real Keycloak (`LwsAuthIT`) plus focused unit tests (SSRF, SAML XSW/XXE, did:key, SPARQL injection).

### Residual issues

These are **security/ops**, not “wrong suite invented”:

1. **DNS rebinding SSRF** residual on unauthenticated OpenID/SSI CID verify (resolve-once vs connect-time DNS).
2. **WebID attribute trust** on issuance (`LWSSubMapper`) if user-writable attributes are enabled.
3. **SAML verify trust model** (caller-supplied cert) can be misused by RPs.
4. **Internal IP leakage** in client-facing block errors.
5. Unauthenticated verify → **outbound amplification / DoS** (fetch before signature).
6. No **jti** replay cache; OpenID **aud** deferred by design.

---

## Scorecard

| Suite / area | Correct core model? | Completeness | Main residual issues |
|--------------|---------------------|--------------|----------------------|
| **OpenID** | Yes | High shape / medium claim-strict | `aud`/`azp`; DNS rebinding on fetch; WebID attribute issuance |
| **SSI CID** | Yes | High | `iat`/AS-bound `aud`; weaker `id==sub`; alg pin consistency |
| **SAML** | Yes | High (stronger than min spec) | Public verify + caller cert misread as deployment trust |
| **did:key** | Yes | High | `iat`; AS-bound `aud`; limited multicodec set |
| **SPI / packaging** | Yes | High | Version pin docs vs runtime |
| **LWS Core storage** | N/A | Out of scope | Use `lws-server` |

---

## Relationship to `lws-server`

```text
                    lws-authn (Keycloak)                 lws-server (storage)
OpenID              Issue ID Token (sub=WebID)          Accept / validate ID Token
                    Host CID + OpenIdProvider           CID trust + discovery + JWKS
                    POST /lws/verify

SSI CID             Host CID + keys                     Accept self-issued JWT
                    POST /lws-ssi-cid/verify            Dereference CID by kid

SAML                Verify utility (+ Keycloak IdP)     Accept if IdP certs configured

did:key             POST /lws-ssi-did-key/verify        Accept self-issued did:key JWT
```

Together they cover the ecosystem. **Neither alone is the full LWS product.** For protocol fidelity of *credentials*, `lws-authn` is often **tighter** (especially SAML XSW, `aud` presence on self-issued suites) than the storage RP path in `lws-server`.

---

## Bottom line

**Yes — `lws-authn` correctly implements the four LWS authentication suites** in the sense that matters for a Keycloak extension: correct credential shapes, trust establishment paths, signature validation, and (for OpenID / SSI CID) issuance + CID hosting.

What it is **not**:

1. A **formal Rec-level conformance certificate** (suites are unofficial proposals).  
2. **Bug-free / internet-hardened by default** (DNS rebinding residual, error leakage, WebID attribute footgun, SAML trust semantics).  
3. An LWS **storage** or the non-auth protocol suites (core CRUD, notifications, search).

### Ship posture (protocol fidelity)

**Ship with fixes** — suite algorithms and structure are sound; production on the public internet should address SSRF residual, error sanitization, WebID attribute policy, and SAML verify documentation/constraints before treating verify endpoints as deployment-level trust oracles.

### Suggested next steps

1. Mitigate DNS rebinding on verifier HTTP (pin or re-check peer addresses).  
2. Generic client errors for blocked fetches; detailed reasons server-side only.  
3. Document/enforce admin-only WebID attributes; clarify SAML trust model in API responses.  
4. Shared `algMatchesKey` for SSI CID; optional `expected_audience` / `jti` for high-security RPs.  
5. Expand unit tests for OpenID and SSI CID verification paths beyond the container IT.
