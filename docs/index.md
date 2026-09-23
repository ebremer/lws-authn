---
title: Home
nav_order: 1
---

# lws-authn — Keycloak providers for LWS authentication suites

A [Keycloak](https://www.keycloak.org/) **26.7.4** extension implementing the authentication suites of
the W3C [Linked Web Storage (LWS)](https://www.w3.org/TR/lws10-core/) 1.0 protocol, in which a **signed
token bound to an identity** is used as an authentication credential — the three current suites, plus
the discontinued fourth for callers that still use it:

- [**OpenID Connect**](https://w3c.github.io/lws-protocol/lws10-authn-openid/) — Keycloak is the
  OpenID Provider; the ID Token's `sub` is a WebID whose controlled identifier document (CID) names
  this Keycloak as its `OpenIdProvider` service.
- [**Self-signed Identity (Controlled Identifiers)**](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/) —
  an agent self-signs a JWT (`sub == iss == client_id`) with a key its identifier's controlled
  identifier document lists for `authentication`, as a `JsonWebKey` or `Multikey`. The identifier is an
  HTTPS URI, or a **DID** — `did:key` or `did:web` — whose DID document is that controlled identifier
  document.
- [**SAML 2.0**](https://w3c.github.io/lws-protocol/lws10-authn-saml/) — the credential is a signed
  SAML 2.0 `<Response>` whose `<NameID>` is the subject; trust in the IdP is established **out of band**.
- ~~[**Self-signed `did:key`**](https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/)~~ —
  **discontinued** by the Working Group on 18 September 2026, "in favor of lws10-authn-ssi-cid, which
  subsumes this specification". The self-signed CID suite now verifies `did:key` subjects itself; this
  suite's endpoint still answers, and marks every response deprecated.

The OpenID and self-signed-CID suites dereference the subject's
[Controlled Identifier Document](https://www.w3.org/TR/cid-1.0/) and use **Apache Jena 6.2.0** for RDF;
a `did:key` resolves locally with pure JDK crypto and a `did:web` is fetched over HTTPS; SAML uses
Keycloak's SAML library for XML signature validation.

---

## Authentication suites

| Suite | Keycloak's role | Credential | How the verifier gets the key | Endpoint | Token type URI |
|-------|-----------------|------------|-------------------------------|----------|----------------|
| OpenID Connect | OP + CID host + verifier | ID Token (JWT); `sub` = WebID | OIDC Discovery on `iss` (found via the CID service) | `/realms/{realm}/lws` | `…token-type:id_token` |
| Self-signed CID | CID host + verifier | self-issued JWT; `sub`==`iss`==`client_id`, an HTTPS URI, `did:key` or `did:web` | the `authentication` method the `kid` names, in the subject's CID or DID document (`publicKeyJwk` or `publicKeyMultibase`) | `/realms/{realm}/lws-ssi-cid` | `…token-type:jwt` |
| SAML 2.0 | SAML IdP + verifier | signed SAML `<Response>`; subject = `<NameID>` | **out-of-band** IdP certificate | `/realms/{realm}/lws-saml` | `…token-type:saml2` |
| *Self-signed `did:key` — discontinued, deprecated* | verifier only | self-issued JWT; `sub` = `did:key` | **decoded from the `did:key`** identifier itself | `/realms/{realm}/lws-ssi-did-key` | `…token-type:jwt` |

The suites are independent; deploy the single JAR and use any of them.

## What it provides

**OpenID Connect suite**

| Component | Keycloak SPI | Purpose |
|-----------|--------------|---------|
| `openid.LWSSubMapper` | `ProtocolMapper` (OIDC) | Sets `sub` to the user's WebID so ID Tokens are usable as LWS credentials. |
| `openid.resource.LWSResourceProvider` | `RealmResourceProvider` (`lws`) | Serves the CID (with the `OpenIdProvider` service) and a credential verifier. |
| `openid.verify.LWSCredentialVerifier` | — | Dereference `sub` → locate service → OIDC discovery → validate JWT. |

**Self-signed CID suite**

| Component | Keycloak SPI | Purpose |
|-----------|--------------|---------|
| `ssicid.resource.SsiCidResourceProvider` | `RealmResourceProvider` (`lws-ssi-cid`) | Serves the CID publishing the user's public key(s) as `authentication` methods, and a verifier. |
| `ssicid.verify.SelfSignedCidVerifier` | — | Check `sub==iss==client_id` → dereference `sub` (HTTPS) or resolve it (DID) → select the `authentication` method by `kid` → validate signature. |
| `ssicid.cid.SelfSignedControlledIdentifierDocument` | — | Builds the CID with `publicKeyJwk` verification methods. |
| `did.Dids` | — | DID syntax; expands a `did:key` into its DID document; maps a `did:web` to its HTTPS URL. |
| `did.DidKey` | — | Multibase/multicodec codec for `did:key` identifiers and `Multikey` values; Ed25519, P-256, P-384, P-521, pure JDK. |

**SAML 2.0 suite**

| Component | Keycloak SPI | Purpose |
|-----------|--------------|---------|
| `saml.resource.SamlResourceProvider` | `RealmResourceProvider` (`lws-saml`) | Verifies a signed SAML 2.0 Response against a supplied (out-of-band) IdP certificate. |
| `saml.verify.SamlCredentialVerifier` | — | Validate the XML signature → read `<NameID>`/`<Issuer>` → enforce the validity window and audience. |

**Self-signed `did:key` suite** (discontinued; the endpoint is deprecated)

| Component | Keycloak SPI | Purpose |
|-----------|--------------|---------|
| `ssididkey.resource.DidKeyResourceProvider` | `RealmResourceProvider` (`lws-ssi-did-key`) | Verifies a self-issued `did:key` JWT, and marks every response deprecated (RFC 9745). |
| `ssididkey.verify.SelfSignedDidKeyVerifier` | — | The discontinued draft's algorithm, unchanged: check `sub==iss==client_id` is a `did:key` → decode the key from it → validate signature. |

The OpenID and self-signed-CID suites serialize CIDs with Jena as JSON-LD / Turtle / N-Triples / RDF/XML.

---

## Where to go next

| Page | What it covers |
|---|---|
| [Build and deploy](build.md) | Building the provider JAR, and deploying it into Keycloak. |
| [Install guide](INSTALL.md) | Deploying this on a server, start to finish. |
| [Walkthroughs](walkthroughs.md) | A walkthrough per suite, each with a runnable demo script. |
| [Reference](reference.md) | Each suite's configuration and endpoints, every setting, the security hardening and the limitations — and **the conformance statement**: which normative requirements each suite enforces, which are deferred to the relying party, and what a `"valid": true` actually asserts. Read it before integrating. |
| [Changelog](CHANGELOG.md) | What changed, and **what breaks on upgrade**. |
| [Security policy](SECURITY.md) | Reporting a vulnerability, and what is deliberate rather than a bug. |
| [Contributing](CONTRIBUTING.md) | Building, testing, and the conventions this codebase expects. |
