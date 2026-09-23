---
title: Walkthroughs
nav_order: 4
has_children: true
has_toc: false
---

# Walkthroughs

One per suite. Each starts from a freshly deployed provider, ends with a credential that verifies, and
explains what an LWS server does with it. Each has its own prerequisites; all of them assume Keycloak
is running with `lws-authn` deployed — see [Build and deploy](build.md).

| Walkthrough | What you end up with | Demo script |
|-------------|----------------------|-------------|
| [OpenID Connect](walkthrough-openid.md) | An ID Token whose `sub` is a WebID; Keycloak issues the token and hosts the document the WebID resolves to. | [`scripts/lws-demo.sh`](https://github.com/ebremer/lws-authn/blob/master/scripts/lws-demo.sh) |
| [Self-signed CID](walkthrough-ssi-cid.md) | A JWT the agent signs itself, verified against the public key Keycloak publishes in the agent's controlled identifier document. | [`scripts/ssi-cid-demo.sh`](https://github.com/ebremer/lws-authn/blob/master/scripts/ssi-cid-demo.sh) |
| [SAML 2.0](walkthrough-saml.md) | A signed SAML Response, verified against an IdP certificate obtained out of band. | None — producing a signed Response takes a SAML login flow. |
| [Self-signed did:key](walkthrough-ssi-did-key.md) | A JWT signed with the key its `did:key` identifier embeds; nothing is hosted. Verified by the self-signed CID suite; the separate `did:key` suite was discontinued. | [`scripts/ssi-did-key-demo.sh`](https://github.com/ebremer/lws-authn/blob/master/scripts/ssi-did-key-demo.sh) |

The demo scripts are the *fast path* of each walkthrough: one command that does everything the
walkthrough then does by hand. Run them from a checkout of the
[repository](https://github.com/ebremer/lws-authn). Each reads its settings from the environment —
`KC_URL`, `REALM` and the rest are listed at the top of the script — and defaults to `kc.sh start-dev`
at `http://localhost:8080` with the bootstrap admin `admin` / `admin`.
