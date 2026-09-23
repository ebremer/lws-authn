---
title: Configuration
parent: Reference
nav_order: 2
---

# Configuration

## Securing the verify endpoints

The four `…/verify` endpoints are **authenticated by default**. Verification is expensive out of
proportion to the request that triggers it: for the OpenID and self-signed-CID suites a single POST
makes this server dereference a URL the caller chose, run OpenID Connect Discovery against it and
fetch its JWKS — all *before* the credential's signature is known good, because that is the order the
specification's cold-trust algorithm requires. Open to anonymous callers that is request
amplification, a network-probe oracle and a cheap denial of service.

| Setting | `Config.Scope` key | System property | Environment variable | Default |
|---|---|---|---|---|
| Mode | `access` | `lws.authn.verify.access` | `LWS_AUTHN_VERIFY_ACCESS` | `bearer` |
| Shared secret | `secret` | `lws.authn.verify.secret` | `LWS_AUTHN_VERIFY_SECRET` | — |
| Required realm role | `role` | `lws.authn.verify.role` | `LWS_AUTHN_VERIFY_ROLE` | — |
| Requests per minute, per caller | `rate-limit` | `lws.authn.verify.rateLimit` | `LWS_AUTHN_VERIFY_RATE_LIMIT` | `60` |

- **`bearer`** (default) — the caller presents a Keycloak access token for the realm. Set `role` to
  additionally require a realm role.
- **`secret`** — the caller presents a pre-shared secret as `Authorization: Bearer <secret>`, for a
  verifier that is not a Keycloak client. Configuring `secret` mode with no secret falls back to
  `bearer`; it never fails open.
- **`public`** — no caller authentication. This is the pre-existing behaviour, and is now opt-in.

> **The `Authorization` header changed meaning.** In `bearer` and `secret` mode it carries the
> **caller's** credential, so the credential being verified must be sent as the `credential` form
> parameter. Only in `public` mode does `Authorization: Bearer …` still fall back to meaning "the
> credential to verify". If you were relying on that form, either send the credential in the body or
> set the mode to `public` explicitly.

Rate limiting applies in every mode, including `public`, and is enforced before the caller is
authenticated. Set `rate-limit` to `0` to turn it off.

Set the mode with either `kc.sh build --spi-realm-restapi-extension--lws--access=public` (repeat per
provider id: `lws`, `lws-ssi-cid`, `lws-saml`) or, with no rebuild, the environment
variable `LWS_AUTHN_VERIFY_ACCESS=public`.

### What each status means

A `/verify` status is about **the request**, never about the credential in it. The credential's verdict
is in the body:

| Status | Meaning |
|---|---|
| `200` | The request was answered. Read `valid` — `true` or `false`. |
| `400` | The request could not be read: a missing or unparseable parameter. |
| `401` / `403` | **You** may not use this endpoint. Carries a `WWW-Authenticate` challenge (RFC 9110 §15.5.2). |
| `404` | This suite is not enabled on this realm. |
| `429` | Rate limited; retry shortly. |

> **A rejected credential is a `200` with `"valid": false`.** Until this release it was a bare `401`
> with no challenge — which RFC 9110 §15.5.2 forbids, and which said the wrong thing anyway: the
> request *was* authorized, and the server answered it. A client that treated any non-`200` as
> "endpoint unavailable" now sees the verdict it was asking for. Check `valid`, not the status.

Every non-`200` carries `application/json` of one shape — `{"error": …, "error_description": …}` —
whichever endpoint and whichever status produced it.

---

## Configuration reference

Every setting is read from the provider's `Config.Scope` first, then a system property, then an
environment variable, then a compiled-in default. `Config.Scope` is the supported surface
(`kc.sh build --spi-realm-restapi-extension--<provider>--<key>=<value>`, where `<provider>` is `lws`,
`lws-ssi-cid` or `lws-saml`) and the only one that can differ per provider; the
environment variable is what a container deployment can set without rebuilding the image.

**Per provider:**

| Setting | Scope key | System property | Environment variable | Default |
|---|---|---|---|---|
| Serve this suite at all | `enabled` | `lws.authn.enabled` | `LWS_AUTHN_ENABLED` | `true` |
| Audience to require when the request names none | `audience` | `lws.authn.audience` | `LWS_AUTHN_AUDIENCE` | — |
| `Cache-Control: max-age` on a served CID | `cid-cache-seconds` | `lws.authn.cid.cacheSeconds` | `LWS_AUTHN_CID_CACHE_SECONDS` | `300` |
| CID requests per minute, per caller | `cid-rate-limit` | `lws.authn.cid.rateLimit` | `LWS_AUTHN_CID_RATE_LIMIT` | `600` |

Plus the four verify-access settings in the table above.

**Server-wide** (read from whichever provider's scope sets them; a provider that says nothing about a
setting leaves it alone):

| Setting | Scope key | System property | Environment variable | Default |
|---|---|---|---|---|
| SSRF allow-list (comma-separated hosts) | `allowed-internal-hosts` | `lws.authn.allowedInternalHosts` | `LWS_AUTHN_ALLOWED_INTERNAL_HOSTS` | — |
| Outbound fetch timeout (ms) | `http-timeout-millis` | `lws.authn.http.timeoutMillis` | `LWS_AUTHN_HTTP_TIMEOUT_MILLIS` | `5000` |
| Outbound response cap (bytes) | `http-max-response-bytes` | `lws.authn.http.maxResponseBytes` | `LWS_AUTHN_HTTP_MAX_RESPONSE_BYTES` | `262144` |
| Clock skew allowed on `exp`/`nbf`/`<Conditions>` (s) | `clock-skew-seconds` | `lws.authn.clockSkewSeconds` | `LWS_AUTHN_CLOCK_SKEW_SECONDS` | `60` |

Out-of-range values are clamped rather than honoured (timeout 100 ms–60 s, response cap 1 KiB–16 MiB,
skew 0–600 s), and a value that will not parse falls back to the default.

**Per realm.** `enabled` is the one setting realms of the same server sensibly differ on, so it also
honours a realm attribute — `lws.authn.<providerId>.enabled` (for example
`lws.authn.lws-saml.enabled`) set to `true` or `false` overrides the provider-wide flag for that realm
alone. A disabled suite answers `404` on both its endpoints.
