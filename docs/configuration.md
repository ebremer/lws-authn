---
title: Configuration
parent: Reference
nav_order: 2
---

# Configuration

## Securing the verify endpoints

The three `…/verify` endpoints are **authenticated by default**. Verification is expensive out of
proportion to the request that triggers it: for the OpenID and self-signed-CID suites a single POST
makes this server dereference a URL the caller chose, run OpenID Connect Discovery against it and
fetch its JWKS — all *before* the credential's signature is known good, because that is the order the
specification's cold-trust algorithm requires. Open to anonymous callers that is request
amplification, a network-probe oracle and a cheap denial of service.

| Setting | `Config.Scope` key | System property | Environment variable | Default |
|---|---|---|---|---|
| Mode | `access` | `lws.authn.verify.access` | `LWS_AUTHN_VERIFY_ACCESS` | `bearer` |
| Shared secret | `secret` | `lws.authn.verify.secret` | `LWS_AUTHN_VERIFY_SECRET` | — |
| Required realm role (`*`: any user of the realm) | `role` | `lws.authn.verify.role` | `LWS_AUTHN_VERIFY_ROLE` | `lws-verifier` |
| Requests per minute, per caller | `rate-limit` | `lws.authn.verify.rateLimit` | `LWS_AUTHN_VERIFY_RATE_LIMIT` | `60` |

- **`bearer`** (default) — the caller presents a Keycloak access token for the realm, **and must hold
  the realm role `role` names: `lws-verifier` unless you name another.** Create that role in each realm
  that serves the verify endpoints and grant it to whatever calls them — normally your authorization
  server's service account, not end users. Until somebody holds it, every bearer caller gets a `403`,
  and the server log says once per realm that the role is missing. The role is checked against the
  user's role mappings as they are *now* — directly, through a composite role or through a group — so
  taking it away takes effect at once, not when the caller's token expires. `role=*` admits any user
  of the realm, which was the default before; it logs a warning at startup, and is only for a realm
  whose every user you trust to make this server fetch URLs of their choosing.
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
authenticated, per caller **address** — an IPv6 address by its `/64`, since one subscriber is routinely
given a whole one. In `bearer` mode each authenticated **user** has a bucket of the same size as well,
which no header can spoof. Set `rate-limit` to `0` to turn both off.

> **Behind a reverse proxy, the address is whatever the proxy says.** If it passes on the client's own
> `X-Forwarded-For` (nginx's `$proxy_add_x_forwarded_for` appends to it), every request can name a
> fresh address and the address bucket is no limit at all. Have the proxy overwrite the header
> (`proxy_set_header X-Forwarded-For $remote_addr;`) and tell Keycloak to believe only the proxy
> (`proxy-trusted-addresses=127.0.0.1`); [INSTALL step 12](INSTALL.md#12-terminate-tls-with-nginx--certbot)
> does both.

Set the mode in `keycloak.conf` (`spi-realm-restapi-extension--lws--access=public`, repeated per
provider id: `lws`, `lws-ssi-cid`, `lws-saml`), on `kc.sh start`
(`--spi-realm-restapi-extension--lws--access=public`), or with the environment variable
`LWS_AUTHN_VERIFY_ACCESS=public` — **not on `kc.sh build`**, which drops it; see
[Runtime, not build time](#runtime-not-build-time).

### What each status means

A `/verify` status is about **the request**, never about the credential in it. The credential's verdict
is in the body:

| Status | Meaning |
|---|---|
| `200` | The request was answered. Read `valid` — `true` or `false`. |
| `400` | The request could not be read: a missing or unparseable parameter, or a `credential` over 256 KiB (262 144 characters). |
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
environment variable, then a compiled-in default. `Config.Scope` is the supported surface —
`spi-realm-restapi-extension--<provider>--<key>=<value>` in `keycloak.conf`, or the same with a leading
`--` on `kc.sh start`, where `<provider>` is `lws`, `lws-ssi-cid` or `lws-saml` — and the only one that
can differ per provider; the environment variable is what a container deployment can set without
rebuilding the image.

### Runtime, not build time

Every setting here except `enabled` is a **runtime** option. Keycloak keeps only build-time options
from `kc.sh build` — for a provider, the keys ending in `-provider`, `-enabled` or `-provider-default` —
and drops anything else with no more than "run time options were found, but will be ignored during
build time" in the build's output. A `role`, `audience` or `allowed-internal-hosts` given to `kc.sh
build` is therefore simply not set, and the server starts without it. Put them in `keycloak.conf`, on
`kc.sh start`, or in the environment.

To see what is actually in force, read the startup log. Each provider logs one line and the server-wide
settings one more:

```
lws-authn provider 'lws' settings in force: enabled=true, access=bearer, role=lws-verifier, rate-limit=60/min, audience=(none), cid-cache-seconds=300, cid-rate-limit=600/min
lws-authn server-wide settings in force: allowed-internal-hosts=[], http-timeout-millis=5000, http-deadline-millis=10000, http-max-response-bytes=262144, http-max-concurrent-per-caller=4, clock-skew-seconds=60
```

A shared secret is shown only as `secret=(set)`.

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
| SSRF allow-list (comma-separated hosts); also the only hosts plain `http` is fetched from | `allowed-internal-hosts` | `lws.authn.allowedInternalHosts` | `LWS_AUTHN_ALLOWED_INTERNAL_HOSTS` | — |
| Outbound fetch timeout (ms) | `http-timeout-millis` | `lws.authn.http.timeoutMillis` | `LWS_AUTHN_HTTP_TIMEOUT_MILLIS` | `5000` |
| Outbound response cap (bytes) | `http-max-response-bytes` | `lws.authn.http.maxResponseBytes` | `LWS_AUTHN_HTTP_MAX_RESPONSE_BYTES` | `262144` |
| Outbound fetch deadline, whole exchange (ms) | `http-deadline-millis` | `lws.authn.http.deadlineMillis` | `LWS_AUTHN_HTTP_DEADLINE_MILLIS` | `10000` |
| Outbound fetches one caller may have in flight | `http-max-concurrent-per-caller` | `lws.authn.http.maxConcurrentPerCaller` | `LWS_AUTHN_HTTP_MAX_CONCURRENT_PER_CALLER` | `4` |
| Clock skew allowed on `exp`/`nbf`/`<Conditions>` (s) | `clock-skew-seconds` | `lws.authn.clockSkewSeconds` | `LWS_AUTHN_CLOCK_SKEW_SECONDS` | `60` |

Out-of-range values are clamped rather than honoured (timeout 100 ms–60 s, response cap 1 KiB–16 MiB,
deadline 100 ms–120 s, fetches in flight 1–64, skew 0–600 s), and a value that will not parse falls back
to the default.

The **timeout** bounds each step of a fetch — waiting for a pooled connection, connecting, each read —
and the **deadline** bounds all of them together: a server that sends one byte just inside the timeout,
every time, is still cut off at the deadline. A caller over its **in-flight** share is refused at once
rather than queued, so one caller cannot occupy the connection pool every verifier shares.

**Per realm.** `enabled` is the one setting realms of the same server sensibly differ on, so it also
honours a realm attribute — `lws.authn.<providerId>.enabled` (for example
`lws.authn.lws-saml.enabled`) set to `true` or `false` overrides the provider-wide flag for that realm
alone. A disabled suite answers `404` on both its endpoints.
