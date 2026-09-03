# Security Policy

`lws-authn` decides whether a credential is genuine. A bug here is not a crash — it is an
authentication bypass, and the failure is silent: a verifier that wrongly *rejects* gets reported by
its users, and one that wrongly *accepts* does not. Please treat findings accordingly.

## Reporting a vulnerability

**Email <erich@ebremer.com>.** Please do not open a public issue for a suspected vulnerability.

Include whatever you have — a description of the flaw and how you found it is useful even without a
working exploit:

- which suite and endpoint (`lws`, `lws-ssi-cid`, `lws-saml`, `lws-ssi-did-key`)
- the version or commit, and the Keycloak version it was running under
- a credential or document that reproduces it, if you have one (a self-signed test key is fine;
  please do not send real credentials)
- what you expected to happen and what happened

You should get an acknowledgement within a few days. This is a small project with no paid security
team and no bug-bounty programme; what it offers is a straight answer, credit in the release notes if
you want it, and a fix.

## What counts

**In scope** — anything that makes a verifier return `"valid": true` for a credential it should
refuse, or that reaches beyond the verifier:

- accepting a credential that is expired, unsigned, signed by the wrong key, or issued for a different
  relying party or audience
- accepting a controlled identifier document that does not describe the subject, or one whose
  verification method the subject does not control
- algorithm confusion, signature stripping, SAML signature wrapping, XXE, JSON-LD or SPARQL injection
- making the server fetch a URL it should not (SSRF), including anything that gets past `SsrfGuard` —
  DNS rebinding, redirects, an allow-list bypass, or address parsing
- disclosing private key material, internal addresses, or another realm's data through any endpoint
- a `verify` endpoint reachable without the caller authentication its configuration requires

**Out of scope** — real, but not bugs in this project:

- **The SAML verifier trusts the certificate the caller supplies.** That is the suite's model: SAML
  trust is established out of band, so `POST …/lws-saml/verify` answers "is this Response signed by
  *that* certificate", not "does this deployment trust that IdP". Anyone can therefore get
  `"valid": true` for an assertion they signed themselves with a certificate they also supplied. That
  is the API doing its job. Treating its answer as a deployment-level trust decision is a relying-party
  bug — see `COMPLIANCE.md`.
- **Identifier enumeration on `cid/{userId}`.** A controlled identifier is a URL other people
  dereference; an identity document that needed a credential would not be dereferenceable. The ids are
  random UUIDs and the endpoint is rate limited. See `CidEndpoint`.
- **A misconfigured deployment.** Notably: an unmanaged attribute policy of `ENABLED` rather than
  `ADMIN_EDIT`, which lets an end user write their own `lws_jwk` or WebID attribute and therefore mint
  credentials for an identity they should not control. `INSTALL.md` step 9f covers this; a report that
  a deployment configured that way is exploitable is a documentation issue, and welcome as one.
- Findings in Keycloak itself — please report those to
  [the Keycloak project](https://github.com/keycloak/keycloak/security/policy).
- Denial of service by an authenticated caller who is within their configured rate limit.

## Supported versions

Development is on `master` against a pinned Keycloak version (see `INSTALL.md`, "Version matrix").
There is no long-term support branch: fixes land on `master` and are described in `CHANGELOG.md`. If
you are running an older build, expect the fix to come as "upgrade", and check the changelog for
breaking changes before you do.

## Hardening this project has already done

Not a claim of completeness — context, so a report can say something new. Each is covered by tests
(`mvn test` for unit, `mvn verify` for the container integration test), and the reasoning is in
`README.md` under "Security" and in `TODO.md`:

- `verify` endpoints authenticated by default, rate limited, and answering `200` with `"valid": false`
  rather than a bare `401`
- SSRF vetting installed as the HTTP client's **DNS resolver**, so the addresses approved are the
  addresses connected to; redirects disabled independently of Keycloak's setting
- responses carry no upstream status codes, resolved addresses or exception text — only a `traceId`
- private key material refused rather than trimmed before publication
- SAML: XSW-resistant navigation, DTDs disallowed, `<Status>`, certificate validity and bearer
  `<SubjectConfirmationData>` all checked
- algorithm pinned to the published key on every suite; `alg: none` and unknown `crit` refused
- JSON-LD contexts resolved from copies bundled in the JAR, never fetched
