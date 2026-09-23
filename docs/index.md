---
title: Home
nav_order: 1
---

# lws-authn

A [Keycloak](https://www.keycloak.org/) **26.7.4** extension implementing the authentication suites of
the W3C [Linked Web Storage (LWS)](https://www.w3.org/TR/lws10-core/) 1.0 protocol, in which a **signed
token bound to an identity** is used as an authentication credential. It ships as a single provider
JAR, and the suites are independent: deploy the JAR and use any of them, each at its own endpoint.

## The suites

| Suite | Credential | How the verifier gets the key | Walkthrough |
|-------|------------|-------------------------------|-------------|
| [OpenID Connect](https://w3c.github.io/lws-protocol/lws10-authn-openid/) | ID Token (JWT) whose `sub` is a WebID | OpenID Connect Discovery on the issuer that the subject's controlled identifier document names | [OpenID Connect](walkthrough-openid.md) |
| [Self-signed Identity (Controlled Identifiers)](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/) | self-issued JWT; `sub` == `iss` == `client_id`, an HTTPS URI, `did:key` or `did:web` | the `authentication` method the `kid` names, in the subject's controlled identifier or DID document | [Self-signed CID](walkthrough-ssi-cid.md) |
| [SAML 2.0](https://w3c.github.io/lws-protocol/lws10-authn-saml/) | signed SAML 2.0 `<Response>`; the subject is its `<NameID>` | an IdP certificate the verifier already holds — trust is established **out of band** | [SAML 2.0](walkthrough-saml.md) |
| *[Self-signed `did:key`](https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/) — discontinued* | self-issued JWT whose `sub` is a `did:key` | decoded from the `did:key` identifier itself | [Self-signed did:key](walkthrough-ssi-did-key.md) |

The Working Group discontinued the `did:key` suite on 18 September 2026, "in favor of
lws10-authn-ssi-cid, which subsumes this specification". The self-signed CID suite now verifies
`did:key` subjects itself; the old suite's endpoint still answers, and marks every response deprecated.

## Getting started

1. **Build and deploy the provider.** `mvn clean package` (JDK 21+) produces
   `target/lws-authn-<version>.jar`; copy it into Keycloak's `providers/` directory and run
   `kc.sh build`. The README's [Build](https://github.com/ebremer/lws-authn/blob/master/README.md#build)
   and [Deploy](https://github.com/ebremer/lws-authn/blob/master/README.md#deploy) sections have the
   detail, and the [install guide](https://github.com/ebremer/lws-authn/blob/master/INSTALL.md) takes a
   server deployment from start to finish.
2. **Follow a [walkthrough](walkthroughs.md).** Each takes a freshly deployed provider to a credential
   that verifies — by hand, or in one command with its demo script.
3. **Read the [conformance statement](https://github.com/ebremer/lws-authn/blob/master/COMPLIANCE.md)
   before integrating.** It says which normative requirements each suite enforces, which are left to
   the relying party, and what a `"valid": true` actually asserts.

The `…/verify` endpoints are authenticated by default: the caller presents its own access token, and
the credential being verified travels in the request body. See
[Securing the verify endpoints](https://github.com/ebremer/lws-authn/blob/master/README.md#securing-the-verify-endpoints).

## Reference

The rest of the documentation lives in the repository, next to the code:

| Document | What it covers |
|----------|----------------|
| [`README.md`](https://github.com/ebremer/lws-authn/blob/master/README.md) | Building, deploying, every endpoint, the configuration reference, and the security model. |
| [`INSTALL.md`](https://github.com/ebremer/lws-authn/blob/master/INSTALL.md) | Deploying this on a server, start to finish. |
| [`COMPLIANCE.md`](https://github.com/ebremer/lws-authn/blob/master/COMPLIANCE.md) | **The conformance statement** — which normative requirements each suite enforces, which are deferred to the relying party, and what a `"valid": true` actually asserts. |
| [`CHANGELOG.md`](https://github.com/ebremer/lws-authn/blob/master/CHANGELOG.md) | What changed, and **what breaks on upgrade**. |
| [`SECURITY.md`](https://github.com/ebremer/lws-authn/blob/master/SECURITY.md) | Reporting a vulnerability, and what is deliberate rather than a bug. |
| [`CONTRIBUTING.md`](https://github.com/ebremer/lws-authn/blob/master/CONTRIBUTING.md) | Building, testing, and the conventions this codebase expects. |
| [`TODO.md`](https://github.com/ebremer/lws-authn/blob/master/TODO.md) | The backlog, as a review against the specifications — and the design history of everything already done. |
