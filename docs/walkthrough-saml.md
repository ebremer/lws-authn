# Walkthrough: a SAML 2.0 LWS identity with Keycloak

The [SAML 2.0 suite](https://w3c.github.io/lws-protocol/lws10-authn-saml/) differs from the OpenID and
self-signed suites: the credential is a signed SAML 2.0 `<Response>`, and **trust is established out of
band** — there is no controlled identifier document to dereference and no discovery. A verifier
validates the assertion's XML signature against a *pre-configured* IdP certificate.

## The cast

| Party | Role |
|-------|------|
| **Keycloak + `lws-authn`** | SAML 2.0 IdP that issues signed assertions, **and** a verifier. |
| **A SAML SP / client app** | Initiates SAML login and receives the assertion. |
| **An LWS server** | The verifier — validates the assertion's signature against the IdP certificate it holds out-of-band, and reads the subject from `<NameID>`. |

**The idea:** the subject (controlled identifier / WebID) is carried in `<Subject><NameID>`, the
issuer in `<Issuer>`. Because the spec leaves trust out-of-band, the verifier must already hold the
IdP's signing certificate; LWS adds no discovery mechanism on top of SAML.

---

## Prerequisites

- Keycloak **26.7.0** with the `lws-authn` provider deployed — see the [README](../README.md).
- `curl`, `jq`, `openssl`.

> Unlike the JWT suites, there is **no shell demo** for SAML — producing a signed SAML Response means
> driving a real SAML login flow, not a one-liner. The verifier itself is validated by a JDK
> XML-DSig round-trip (sign a Response, verify it, and confirm tampering / wrong cert / wrong audience
> are rejected). This guide shows how to wire it up with a real IdP.

---

## 1. Configure Keycloak as the SAML IdP

Create a SAML client (your SP) in the realm and arrange for the assertion's `<NameID>` to carry the
user's WebID (controlled identifier) — via the client's *Name ID format* / NameID settings. Keycloak
signs assertions with the realm SAML signing key by default.

## 2. Obtain the IdP signing certificate (out-of-band)

The realm publishes its SAML metadata, including the signing certificate, at the descriptor endpoint:

```bash
KC=https://keycloak.example; REALM=myrealm
# pull the base64 signing cert out of the IdP metadata and wrap it as PEM
CERT=$(curl -s "$KC/realms/$REALM/protocol/saml/descriptor" \
  | grep -o '<ds:X509Certificate>[^<]*' | head -1 | sed 's/<[^>]*>//')
printf -- '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' "$CERT" > idp.pem
openssl x509 -in idp.pem -noout -subject -issuer      # sanity-check it parses
```

A verifier (or LWS server) obtains this certificate once, ahead of time — that is the "out-of-band"
trust establishment the spec refers to.

## 3. Obtain a signed SAML Response

Perform a SAML login against Keycloak with your SP and capture the `SAMLResponse` it posts back (it is
base64-encoded in the POST binding). For ad-hoc testing, tools like a browser's dev tools or a SAML
test SP can capture it. Save the base64 (or decoded XML) to `response.b64`.

## 4. Verify the credential

```bash
curl -s -X POST "$KC/realms/$REALM/lws-saml/verify" \
  -H "Authorization: Bearer $CALLER_ACCESS_TOKEN" \
  --data-urlencode "credential@response.b64" \
  --data-urlencode "certificate@idp.pem" \
  --data-urlencode "audience=https://app.example/SAML" | jq
```

> `Authorization` identifies **you**, the caller: the `…/verify` endpoints are authenticated by
> default. The credential being checked always travels in the request body. See
> [Securing the verify endpoints](../README.md#securing-the-verify-endpoints).

The assertion must also satisfy the parts of SAML 2.0 that make a bearer assertion an authentication
credential, none of which `<Conditions>` implies on its own:

- the Response's `<samlp:StatusCode>` is `urn:oasis:names:tc:SAML:2.0:status:Success`;
- there is exactly one `<SubjectConfirmation>`, with `Method="…:cm:bearer"`;
- its `<SubjectConfirmationData>` carries a `Recipient` — the LWS client identifier, which the suite
  makes mandatory — and a `NotOnOrAfter` that has not passed;
- the IdP certificate you supply is itself inside its validity period. Pass
  `allowExpiredCertificate=true` to override that, but only for offline analysis of an old
  credential — an expired certificate is not a trust anchor.

```json
{
  "valid": true,
  "subject": "https://id.example/end-user",
  "issuer": "https://idp.example",
  "audiences": ["https://app.example/SAML", "https://as.example"],
  "recipient": "https://app.example/SAML",
  "notBefore": "2026-…Z",
  "notOnOrAfter": "2026-…Z",
  "checks": {
    "signaturePresent": true,
    "signatureValid": true,
    "withinValidityWindow": true,
    "audienceMatched": true
  }
}
```

The verifier: validates the enveloped XML signature against the supplied certificate, reads the
subject from `<NameID>` and the issuer from `<Issuer>`, enforces the `<Conditions>` validity window
(±60 s clock skew), and checks the audience restriction.

## 5. Present it to an LWS server

An LWS server does exactly the same: it holds the IdP certificate out-of-band, validates the SAML
Response's signature, and authenticates the request as the `<NameID>` subject. Per the core protocol
the credential is presented as a bearer token (`Authorization: Bearer …`) with token type
`urn:ietf:params:oauth:token-type:saml2`.

---

## Notes

- **Out-of-band trust.** This suite adds no discovery — the verifier must already trust the IdP's
  certificate (e.g. pinned, or taken from the realm metadata as above). Rotating the IdP's SAML key
  means re-distributing the certificate.
- **What is validated.** The XML-DSig signature against the supplied certificate; that the certificate
  is itself within its validity period; the Response's `<samlp:StatusCode>`; a single bearer
  `<SubjectConfirmation>` with a `Recipient` and an unexpired `NotOnOrAfter`; the `<Conditions>` time
  window; and the audience. The verifier does not build an X.509 trust chain or fetch metadata — it
  trusts the certificate you give it, and only checks that the certificate has not expired.
- **Audience / token exchange.** Restrict the assertion's audience to the target server, and use OAuth
  2.0 Token Exchange (RFC 8693, token type `urn:ietf:params:oauth:token-type:saml2`) where a broadly
  scoped assertion must be narrowed.
- **Encrypted assertions / Redirect-binding deflate** are not handled; supply the signed Response as
  XML or base64-encoded XML.
