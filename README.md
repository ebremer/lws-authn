# lws-authn — Keycloak providers for LWS authentication suites

A [Keycloak](https://www.keycloak.org/) **26.7.4** extension implementing the authentication suites of
the W3C [Linked Web Storage (LWS)](https://www.w3.org/TR/lws10-core/) 1.0 protocol, in which a **signed
token bound to an identity** is used as an authentication credential — all three of its suites:

- [**OpenID Connect**](https://w3c.github.io/lws-protocol/lws10-authn-openid/) — Keycloak is the
  OpenID Provider; the ID Token's `sub` is a WebID.
- [**Self-signed Identity (Controlled Identifiers)**](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/) —
  an agent signs its own JWT with a key its controlled identifier document lists; the identifier is an
  HTTPS URI, a `did:key` or a `did:web`.
- [**SAML 2.0**](https://w3c.github.io/lws-protocol/lws10-authn-saml/) — a signed SAML 2.0
  `<Response>` whose `<NameID>` is the subject.

## Documentation

**<https://ebremer.github.io/lws-authn/>** — building and deploying, installing on a server, a
walkthrough per suite, each suite's endpoints, the configuration reference, the conformance statement
and the changelog. Its source is [`docs/`](docs/).

## Quick start

With JDK 21+, Maven, and a Keycloak 26.7.4 install at `$KC_HOME`:

```bash
mvn clean package                                  # builds target/lws-authn-<version>.jar
cp target/lws-authn-*.jar "$KC_HOME/providers/"
"$KC_HOME/bin/kc.sh" build                         # re-augment with the new provider
"$KC_HOME/bin/kc.sh" start                         # or start-dev
```

Then try a suite with its [walkthrough](https://ebremer.github.io/lws-authn/walkthroughs.html); each
has a demo script in [`scripts/`](scripts/).

## Security

Report a vulnerability by email, not in an issue — see the
[security policy](https://ebremer.github.io/lws-authn/SECURITY.html).

## Contributing

See the [contributing guide](https://ebremer.github.io/lws-authn/CONTRIBUTING.html). The backlog is
[`TODO.md`](TODO.md), written as a review against the specifications.

## License

Apache-2.0 — see [`LICENSE`](LICENSE). Every source file carries `SPDX-License-Identifier: Apache-2.0`.
