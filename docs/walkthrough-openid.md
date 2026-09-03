# Walkthrough: create an LWS identity with Keycloak and use it with an LWS server

This guide takes you from a freshly deployed `lws-authn` provider to a working **LWS identity** — a
dereferenceable WebID, issued credentials, and a validation you can reproduce — and explains how an
LWS (Linked Web Storage) server consumes it.

## The cast

| Party | Role |
|-------|------|
| **You** (a user) | Need a **WebID** — a dereferenceable identity URL. |
| **Keycloak + `lws-authn`** | Your **OpenID Provider** (`iss`). Issues the ID Token *and* hosts the document your WebID resolves to. |
| **A client app** | What you log into; it gets the ID Token from Keycloak over normal OIDC. |
| **An LWS server** | The resource server (a Solid-lineage pod/storage). It is the *verifier* — it runs the same algorithm as the provider's `/verify` endpoint. |

**The idea that makes it work:** you never register Keycloak with the LWS server. The server
establishes trust *dynamically* — it dereferences your `sub` (WebID), sees that your own document
names this Keycloak as its `OpenIdProvider`, and only then trusts tokens from that issuer. Your
identity is self-describing.

> If you point the mapper at a **WebID user attribute**, that attribute becomes the credential's
> subject — so it must not be user-writable. Keep the realm's unmanaged attribute policy at
> `ADMIN_EDIT`, or declare the attribute in the user profile with admin-only write permission.
> A user who can set their own `sub` can claim any WebID.

---

## Prerequisites

- Keycloak **26.7.3** with the `lws-authn` provider deployed — see the [README](../README.md) (build
  → copy `target/lws-authn-0.1.0.jar` to `providers/` → `kc.sh build` → `kc.sh start`).
- `curl` and `jq`.
- For a quick local run: `bin/kc.sh start-dev` (bootstrap admin `admin` / `admin`), reachable at
  `http://localhost:8080`.

---

## Fast path — one script

With the provider deployed and Keycloak running locally:

```bash
bash scripts/lws-demo.sh
```

It provisions a realm (`lws-demo`), a client (`lws-app`), the **LWS WebID Subject** mapper and a user
(`alice`), then obtains an ID Token, dereferences the resulting WebID, and runs the credential through
`/verify`. Override anything via env vars, e.g. `KC_URL=https://kc.example ADMIN_PASS=… bash scripts/lws-demo.sh`.

A successful run ends with `valid: true` and prints the WebID — that's your LWS identity.

The rest of this document is the same thing done by hand.

---

## Manual path

### 1. Set up the realm, client, mapper and user

**Either** import the bundled realm:

```bash
# offline import
bin/kc.sh import --file examples/lws-demo-realm.json
# …or drop it in data/import/ and start with --import-realm, or use the Admin UI:
#   Realm selector → Create realm → Resource file = examples/lws-demo-realm.json
```

> The realm references the mapper provider id `lws-webid-sub-mapper`, so the provider must be deployed
> **before** importing.

**Or** do it in the Admin UI:

1. **Create realm** `lws-demo`.
2. **Clients → Create** `lws-app` (OpenID Connect). For this walkthrough enable *Direct access
   grants* so you can fetch tokens with a script; leave *Standard flow* on for real apps.
3. **Clients → lws-app → Client scopes → `lws-app-dedicated` → Add mapper → By configuration →
   LWS WebID Subject.** Leave *WebID user attribute* blank (Keycloak-hosted WebID).
4. **Users → Create** `alice`, then **Credentials →** set password `alice` (not temporary).

### 2. Make Keycloak dereferenceable (for real deployments)

The WebID and discovery documents must be reachable by the LWS server. Set a stable public hostname
(realm **Frontend URL**, or `KC_HOSTNAME` at startup). Locally, `http://localhost:8080` is fine. The
issuer below is assumed to be `http://localhost:8080/realms/lws-demo`.

### 3. Get an ID Token

```bash
ID_TOKEN=$(curl -s -X POST \
  http://localhost:8080/realms/lws-demo/protocol/openid-connect/token \
  -d grant_type=password -d client_id=lws-app -d scope=openid \
  -d username=alice -d password=alice | jq -r .id_token)
```

### 4. Inspect — your `sub` is a WebID

```bash
echo "$ID_TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{sub, iss, aud, azp}'
```

```json
{
  "sub": "http://localhost:8080/realms/lws-demo/lws/cid/2b8a…e1",
  "iss": "http://localhost:8080/realms/lws-demo",
  "aud": "lws-app",
  "azp": "lws-app"
}
```

That `sub` is your identity. Unlike a stock Keycloak token (whose `sub` is an opaque UUID), this one
is a URL you can fetch.

> **Why `azp` here is `lws-app` and not a URL.** LWS core §4.1 says the client identifier **SHOULD** be
> a URI. This demo keeps a bare `lws-app` because it is also a Keycloak client id, which is what you
> type into the console, pass as `client_id` in a token request, and see in every Keycloak tutorial —
> making it a URL here would teach the LWS point at the cost of obscuring the Keycloak one.
>
> It is a SHOULD, and `lws-authn` requires `azp` to be *present* rather than to be a URI, so both forms
> verify. **In production, prefer a URI** — `https://app.example.com/` is a perfectly good Keycloak
> client id, and a globally unique client identifier is what stops two deployments' clients colliding
> in a verifier's audience check. To use one, set it as the client id when you create the client; no
> other change is needed, because `client_id`, `aud` and `azp` all follow it.

### 5. Dereference the WebID (the controlled identifier document)

```bash
SUB=$(echo "$ID_TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r .sub)
curl -s -H 'Accept: text/turtle' "$SUB"
```

```turtle
<http://localhost:8080/realms/lws-demo/lws/cid/2b8a…e1>
        <https://www.w3.org/ns/did#service>
                [ a       <https://www.w3.org/ns/lws#OpenIdProvider> ;
                  <https://www.w3.org/ns/did#serviceEndpoint>
                          <http://localhost:8080/realms/lws-demo> ] .
```

Ask for `application/ld+json`, `application/n-triples`, or `application/rdf+xml` to get other
syntaxes. The document says: *the OpenID Provider for this subject is this Keycloak issuer.*

### 6. Verify the credential

This is exactly what an LWS server does, exposed as an endpoint:

```bash
curl -s -X POST "$(echo "$ID_TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r .iss)/lws/verify" \
  --data-urlencode "credential=$ID_TOKEN" | jq
```

```json
{
  "valid": true,
  "subject": "http://localhost:8080/realms/lws-demo/lws/cid/2b8a…e1",
  "issuer": "http://localhost:8080/realms/lws-demo",
  "checks": {
    "signingAlgorithmNotNone": true,
    "subjectDereferenced": true,
    "openIdProviderServiceLocated": true,
    "issuerDiscoveryMatches": true,
    "jwksResolved": true,
    "signatureValid": true,
    "notExpired": true
  }
}
```

A `valid: true` here means any conformant LWS server will accept the same credential.

### 7. Present it to an LWS server

Your client app presents the ID Token as the LWS credential on requests to the server:

```bash
curl https://pod.example/alice/profile -H "Authorization: Bearer $ID_TOKEN"
```

The server then does what step 6 did — dereferences `sub`, confirms the `OpenIdProvider` service
equals `iss`, runs OpenID Connect Discovery, validates the signature — and authenticates the request
**as your WebID**. Your pod's access rules (ACL/ACP) are written against that WebID, so this is now
*your* identity on that server. No server-side configuration of Keycloak is required.

---

## Bring your own WebID (instead of a Keycloak-hosted one)

If you already own a WebID (e.g. on your own storage), point `sub` at it:

1. Set a user attribute — say `lws_webid` — to your WebID URL (Users → alice → Attributes), or run
   the script with `WEBID_ATTRIBUTE=lws_webid` after setting the attribute.
2. In the **LWS WebID Subject** mapper, set *WebID user attribute* = `lws_webid`.
3. **Host the controlled identifier document yourself**, naming this Keycloak as your OpenID Provider.
   Keycloak only serves documents for Keycloak-hosted WebIDs. The minimum your document must contain:

   ```turtle
   <https://you.example/profile#me>
       <https://www.w3.org/ns/did#service> [
           a <https://www.w3.org/ns/lws#OpenIdProvider> ;
           <https://www.w3.org/ns/did#serviceEndpoint> <https://kc.example/realms/lws-demo>
       ] .
   ```

   or equivalently as JSON-LD:

   ```json
   {
     "@context": ["https://www.w3.org/ns/cid/v1"],
     "id": "https://you.example/profile#me",
     "service": [{
       "type": "https://www.w3.org/ns/lws#OpenIdProvider",
       "serviceEndpoint": "https://kc.example/realms/lws-demo"
     }]
   }
   ```

---

## Production checklist

- **Frontend URL / hostname** — set it so `iss`, the WebID, and discovery are stable and publicly
  dereferenceable; otherwise tokens minted on one host won't validate when fetched from another.
- **HTTPS** — required outside localhost (`sslRequired`).
- **Audience** — the LWS server validates `aud`. If it requires its own URL as the audience, add a
  Keycloak **Audience** mapper or use Resource Indicators (RFC 8707) / OAuth 2.0 Token Exchange
  (RFC 8693, token type `urn:ietf:params:oauth:token-type:id_token`).
- **Turn off Direct Access Grants** — it's enabled here only to make the walkthrough scriptable; real
  apps use the Authorization Code flow.
- **Presentation & DPoP** — *how* the token is attached to LWS requests (plain `Bearer` vs a
  DPoP-bound presentation) is governed by the broader LWS HTTP messaging spec and the specific
  server, not by this authentication sub-spec, which does not mandate DPoP.
- **Ecosystem** — LWS is an in-progress W3C effort building on Solid; concrete servers today are
  largely Solid servers evolving toward it, and a given server may not yet implement this suite's
  CID-based discovery.
