---
title: Install guide
nav_order: 3
---

# Installing Keycloak + the `lws-authn` OpenID Connect provider on Ubuntu

Step-by-step instructions to install [Keycloak](https://www.keycloak.org/) and the **`lws-authn`**
provider — the LWS OpenID Connect ("lws-oidc") authentication suite — on an Ubuntu server that
**already has a recent JDK installed**.

The single provider JAR actually ships every LWS 1.0 authentication suite — OpenID Connect,
self-signed CID (for HTTPS, `did:key` and `did:web` subjects) and SAML 2.0. This guide focuses on
standing up the **OpenID Connect** suite, which mounts at `…/realms/{realm}/lws`; the other endpoints
(`lws-ssi-cid`, `lws-saml`) come along in the same JAR at no extra effort.

The result is a Keycloak server running as a hardened `systemd` service behind an HTTPS reverse
proxy, with the LWS provider registered and verified end-to-end.

> **Only want to try it?** `docker compose up --build --wait` in a checkout starts Keycloak with the
> provider and a demo realm on `http://localhost:8080` — see [Run with Docker](build.md#run-with-docker).
> That is a development setup; this guide is for a server.

---

## Contents

1. [Before you begin](#1-before-you-begin)
2. [Install system packages](#2-install-system-packages)
3. [Verify Java](#3-verify-java)
4. [Create a service account](#4-create-a-service-account)
5. [Download & install Keycloak](#5-download--install-keycloak)
6. [Build the `lws-authn` provider](#6-build-the-lws-authn-provider)
7. [Deploy the provider JAR](#7-deploy-the-provider-jar)
8. [Smoke test in dev mode](#8-smoke-test-in-dev-mode)
9. [Configure Keycloak for production](#9-configure-keycloak-for-production) — including [who may call `/verify`](#9d-decide-who-may-call-verify)
10. [Build the optimized image](#10-build-the-optimized-image)
11. [Run Keycloak as a systemd service](#11-run-keycloak-as-a-systemd-service)
12. [Terminate TLS with nginx + certbot](#12-terminate-tls-with-nginx--certbot)
13. [Verify the OpenID Connect suite end-to-end](#13-verify-the-openid-connect-suite-end-to-end)
14. [Production checklist](#14-production-checklist)
15. [Troubleshooting](#15-troubleshooting)
16. [Upgrading & uninstalling](#16-upgrading--uninstalling)

Throughout, replace **`id.example.com`** with your server's public hostname and every
**`CHANGE_ME…`** with a real secret.

### Version matrix

| Component | Version | Notes |
|-----------|---------|-------|
| Keycloak server | **26.8.0** or a later 26.8 release | The same 26.x minor as `keycloak.version` in the provider's `pom.xml`, which is the release it is built and tested against. **Apply Keycloak's patch releases as they come** — that is where Keycloak's security fixes land — without waiting for the provider to follow. |
| `lws-authn` provider | **0.3.0-SNAPSHOT** | Unreleased work after 0.2.0, the latest release. Produces `lws-authn-0.3.0-SNAPSHOT.jar`. |
| JDK (Keycloak runtime) | **21** | Keycloak 26.x is built and tested on OpenJDK 21. |
| JDK (build) | **21+** | Any JDK ≥ 21 builds it; it compiles to Java 21 bytecode. |

```bash
# Handy shell variables used in the commands below
export KC_VERSION=26.8.0   # or a later 26.8 release
export PROVIDER_VERSION=0.3.0-SNAPSHOT
export KC_HOSTNAME=id.example.com     # your public hostname
```

---

## 1. Before you begin

You need:

- An Ubuntu server (22.04 LTS or 24.04 LTS) with `sudo` access.
- A JDK already installed (this guide assumes so — see [step 3](#3-verify-java)).
- A public DNS **A/AAAA record** pointing `id.example.com` at the server (required for TLS and so
  the LWS WebIDs this server mints are publicly dereferenceable).
- Outbound internet access (to download Keycloak and Maven dependencies).

> **Why the hostname matters for LWS.** The OpenID Connect suite derives each user's WebID and the
> issuer (`iss`) from Keycloak's front-end URL, e.g.
> `https://id.example.com/realms/{realm}/lws/cid/{userId}`. A verifier (an LWS/Solid server) fetches
> that WebID over the network. If the hostname isn't stable and publicly resolvable, tokens minted on
> one host won't validate when the document is fetched from another. Set it correctly in
> [step 9](#9-configure-keycloak-for-production).

---

## 2. Install system packages

```bash
sudo apt update
sudo apt install -y git maven curl jq unzip
```

- `git` + `maven` — to clone and build the provider ([step 6](#6-build-the-lws-authn-provider)). Skip
  these if you build the JAR elsewhere and copy it over.
- `curl` + `jq` — used by the end-to-end verification ([step 13](#13-verify-the-openid-connect-suite-end-to-end)).

> Installing `maven` from apt may pull in a default JDK as a dependency. That's harmless — it does not
> change your default `java`, and Maven will use whatever JDK is on `PATH` (confirm with `mvn -v`).

---

## 3. Verify Java

Your server already has a JDK. Confirm it:

```bash
java -version
```

- **Building** the provider works on any JDK **21 or newer** (it targets Java 21 bytecode via
  `maven.compiler.release=21`), so your "latest Java" is fine for the build.
- **Running Keycloak 26.x** is officially validated on **OpenJDK 21**.

If your latest Java is newer than 21 (e.g. 24/25) and Keycloak later refuses to start or logs an
unsupported-JVM warning, install OpenJDK 21 **alongside** your existing JDK and pin it for the
Keycloak service only (this does not touch your system default):

```bash
sudo apt install -y openjdk-21-jdk
# Note the path — you'll reference it as JAVA_HOME in the systemd unit (step 11):
ls -d /usr/lib/jvm/java-21-openjdk-*    # e.g. /usr/lib/jvm/java-21-openjdk-amd64
```

---

## 4. Create a service account

Run Keycloak under a dedicated, unprivileged system user rather than root:

```bash
sudo groupadd --system keycloak
sudo useradd  --system --gid keycloak \
              --home-dir /opt/keycloak --shell /usr/sbin/nologin keycloak
```

---

## 5. Download & install Keycloak

Download the distribution — the 26.8 release the provider is built against (`26.8.0`) or a later 26.8
patch — and unpack it under `/opt`,
using a version-independent symlink so future upgrades are a one-line switch:

```bash
cd /tmp
curl -fL -O "https://github.com/keycloak/keycloak/releases/download/${KC_VERSION}/keycloak-${KC_VERSION}.tar.gz"

sudo tar -xzf "keycloak-${KC_VERSION}.tar.gz" -C /opt
sudo ln -sfn "/opt/keycloak-${KC_VERSION}" /opt/keycloak
sudo chown -R keycloak:keycloak "/opt/keycloak-${KC_VERSION}"
```

> Optional integrity check: the release page publishes a SHA-256; compare it against
> `sha256sum keycloak-${KC_VERSION}.tar.gz` before unpacking.

`/opt/keycloak` is now `$KC_HOME`. Verify it launches:

```bash
sudo -u keycloak /opt/keycloak/bin/kc.sh --version
```

---

## 6. Build the `lws-authn` provider

You need the file **`lws-authn-0.3.0-SNAPSHOT.jar`**. Pick one option.

### Option A — build on the server (recommended, self-contained)

```bash
git clone https://github.com/ebremer/lws-authn.git /tmp/lws-authn
cd /tmp/lws-authn
mvn -v        # confirm Java 21+
mvn clean package
```

This produces a single, self-contained provider JAR:

```
/tmp/lws-authn/target/lws-authn-0.3.0-SNAPSHOT.jar
```

Apache Jena and its dependencies are shaded in and `commons-codec` is relocated, so the JAR drops
cleanly onto Keycloak's classpath. `mvn clean package` runs the unit tests but **not** the
Docker-based integration test (that's bound to `mvn verify`). To skip tests for a faster build, add
`-DskipTests`.

### Option B — copy a JAR you built elsewhere

If you already ran `mvn clean package` on another machine, copy the artifact over:

```bash
scp target/lws-authn-0.3.0-SNAPSHOT.jar you@id.example.com:/tmp/
```

---

## 7. Deploy the provider JAR

Keycloak loads provider JARs from `$KC_HOME/providers/`:

```bash
sudo cp /tmp/lws-authn/target/lws-authn-${PROVIDER_VERSION}.jar /opt/keycloak/providers/
sudo chown keycloak:keycloak /opt/keycloak/providers/lws-authn-${PROVIDER_VERSION}.jar
```

> Adjust the source path if you used Option B (e.g. `/tmp/lws-authn-0.3.0-SNAPSHOT.jar`).

You'll register it with the server via `kc.sh build` in [step 10](#10-build-the-optimized-image)
(or immediately, in the dev-mode smoke test below).

---

## 8. Smoke test in dev mode

Before layering on a database and TLS, confirm the provider **loads** — this isolates "is the JAR
installed correctly?" from "is my production config right?". Dev mode uses an in-memory H2 database
and plain HTTP, so nothing else needs to be configured.

```bash
sudo -u keycloak env \
  PATH="/usr/local/bin/graalvm/bin:$PATH" \
  KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  /opt/keycloak/bin/kc.sh start-dev
```

On startup Keycloak augments itself with the new JAR. Watch the log for the LWS providers being
registered — you should see the three realm-resource providers and the protocol mapper:

```
lws (org.keycloak.services.resource.RealmResourceProviderFactory)
lws-ssi-cid (org.keycloak.services.resource.RealmResourceProviderFactory)
lws-saml (org.keycloak.services.resource.RealmResourceProviderFactory)
lws-webid-sub-mapper (org.keycloak.protocol.ProtocolMapper)
```

From another shell on the server, confirm the OpenID endpoint is mounted (the master realm has no
users, so a `400`/`404`-style JSON error here is expected and still proves the route is live):

```bash
curl -s http://localhost:8080/realms/master/lws/verify -d 'credential=x' | head
```

Stop the dev server with `Ctrl-C`. Now configure it properly.

---

## 9. Configure Keycloak for production

### 9a. Provision a PostgreSQL database

The dev H2 database is not for production. Install PostgreSQL and create a database:

```bash
sudo apt install -y postgresql
sudo -u postgres psql -c "CREATE USER keycloak WITH PASSWORD 'CHANGE_ME_DB';"
sudo -u postgres psql -c "CREATE DATABASE keycloak OWNER keycloak;"
```

### 9b. Write `keycloak.conf`

Edit `/opt/keycloak/conf/keycloak.conf` (owned by `keycloak`) with the non-secret configuration. The
database password and other secrets are injected as environment variables in
[step 11](#11-run-keycloak-as-a-systemd-service), so they never sit in this file.

```properties
# ---- Database (db vendor is a build-time option) ----
db=postgres
db-url=jdbc:postgresql://localhost:5432/keycloak
db-username=keycloak
# db-password comes from the KC_DB_PASSWORD environment variable (systemd)

# ---- Hostname (CRITICAL for LWS) ----
# The provider derives every WebID and the issuer from this URL.
hostname=https://id.example.com

# ---- Reverse-proxy TLS termination (see step 12) ----
# Keycloak serves plain HTTP on 8080; nginx terminates HTTPS in front of it.
proxy-headers=xforwarded
# Believe X-Forwarded-* only from nginx itself; the rate limits key on the address it forwards.
proxy-trusted-addresses=127.0.0.1,::1
http-enabled=true

# ---- Health endpoints (build-time option; used by systemd/monitoring) ----
health-enabled=true
```

Set ownership and lock down the file:

```bash
sudo chown keycloak:keycloak /opt/keycloak/conf/keycloak.conf
sudo chmod 640 /opt/keycloak/conf/keycloak.conf
```

> **Direct TLS instead of a proxy?** If you'd rather have Keycloak terminate HTTPS itself, drop the
> two proxy lines and instead point it at a certificate:
> ```properties
> https-certificate-file=/etc/keycloak/tls/tls.crt
> https-certificate-key-file=/etc/keycloak/tls/tls.key
> ```
> Keycloak then listens on `:8443`. The reverse-proxy topology in [step 12](#12-terminate-tls-with-nginx--certbot)
> is the more common choice on Ubuntu and is assumed for the rest of this guide.

### 9c. Plan the SSRF allow-list (important for OpenID `/verify`)

The OpenID verifier dereferences URLs taken from the credential — the subject's WebID (`sub`) and the
issuer's discovery document. A built-in SSRF guard **blocks any host that resolves to a loopback,
private, link-local, or otherwise reserved address** (including the `169.254.169.254` cloud-metadata
endpoint).

Because this Keycloak **hosts its own** controlled identifier documents, its OpenID `/verify`
dereferences **itself**. That's fine when `id.example.com` resolves to a public IP the server can
reach. But if the server reaches its own hostname over an internal/loopback address (single-box
setups, split-horizon DNS, or NAT hairpin problems), the guard will block `/verify` unless you
allow-list that host.

You opt specific hosts back in with a comma-separated list, via **any** of:

- environment variable `LWS_AUTHN_ALLOWED_INTERNAL_HOSTS`,
- JVM system property `lws.authn.allowedInternalHosts`, or
- the provider option `spi-realm-restapi-extension--lws--allowed-internal-hosts=…` in `keycloak.conf`,
  or `--spi-realm-restapi-extension--lws--allowed-internal-hosts=…` on `kc.sh start` (set it on any one
  of the three providers; it is a server-wide setting). **Not on `kc.sh build`** — see the note in
  [step 9d](#9d-decide-who-may-call-verify).

We wire the environment variable into the systemd unit in the next steps. For a single-box install
where the server can't reach its own public IP, set it to your hostname (and/or `127.0.0.1`); leave
it empty otherwise.

Every fetch is **https**: a subject, issuer or `jwks_uri` on plain `http` is refused, because anyone on
the network path could substitute its keys. An allow-listed host is the one exception — so a server
that reaches itself as `http://127.0.0.1:8080` works once that address is on the list.

The guard is installed as the **DNS resolver** of the HTTP client the verifiers use, not as a separate
check in front of it, so the addresses it approves are exactly the addresses connected to — there is no
second lookup for a hostile name server to poison. That client also refuses to follow redirects.
Neither property depends on `spi-connections-http-client-default-allow-redirects`, so changing that
server-wide setting cannot open a hole here.

---

### 9d. Decide who may call `/verify`

The three `…/verify` endpoints are **authenticated by default**, because verification is expensive out
of proportion to the request: a single POST makes this server dereference a URL the caller chose, run
OpenID Connect Discovery against it and fetch its JWKS — before the credential's signature is known
good, since that is the order the specification's cold-trust algorithm requires.

| Setting | Environment variable | System property | Default |
|---|---|---|---|
| Mode (`bearer` / `secret` / `public`) | `LWS_AUTHN_VERIFY_ACCESS` | `lws.authn.verify.access` | `bearer` |
| Shared secret (mode `secret`) | `LWS_AUTHN_VERIFY_SECRET` | `lws.authn.verify.secret` | — |
| Required realm role (mode `bearer`; `*` for any user) | `LWS_AUTHN_VERIFY_ROLE` | `lws.authn.verify.role` | `lws-verifier` |
| Requests per minute, per caller | `LWS_AUTHN_VERIFY_RATE_LIMIT` | `lws.authn.verify.rateLimit` | `60` |

The same settings are available as provider options, one per provider id: in `keycloak.conf`
(`spi-realm-restapi-extension--lws--access=public`) or on `kc.sh start`
(`--spi-realm-restapi-extension--lws--access=public`). The environment variables need neither, so they
are what the systemd unit below uses.

> **These are runtime options. Do not pass them to `kc.sh build`.** Keycloak keeps only build-time
> options from a build — for a provider, the keys ending in `-provider`, `-enabled` or
> `-provider-default` — and drops the rest with nothing more than "run time options were found, but
> will be ignored during build time" in the build's output. A `role` or `audience` given to `kc.sh
> build` is simply not set, and the server starts without it. To see what is actually in force, look
> for these lines in the startup log, one per provider and one for the server-wide settings:
>
> ```
> lws-authn provider 'lws' settings in force: enabled=true, access=bearer, role=lws-verifier, rate-limit=60/min, …
> lws-authn server-wide settings in force: allowed-internal-hosts=[…], http-timeout-millis=5000, …
> ```

- **`bearer`** — the caller presents a Keycloak access token for the realm **and holds the realm role
  `lws-verifier`** (or the one `LWS_AUTHN_VERIFY_ROLE` names). In each realm that serves `/verify`,
  create the role (*Realm roles → Create role*) and grant it to the caller — typically the service
  account of the authorization server that verifies credentials (*Clients → that client → Service
  accounts roles → Assign role*). Nobody holds it by default, so until you grant it every bearer caller
  gets a `403`. Do **not** grant it to end users, and do not set `LWS_AUTHN_VERIFY_ROLE=*` (any user of
  the realm) on a realm that lets people register themselves.
- **`secret`** — the caller presents a pre-shared secret as `Authorization: Bearer <secret>`. Choosing
  `secret` without configuring one falls back to `bearer`; it never fails open.
- **`public`** — anonymous, the pre-1.0 behaviour. Only for endpoints already restricted to a trusted
  network by the firewall or reverse proxy.

> **A rejected credential is a `200`, not a `401`.** A `/verify` status is about the request; the
> credential's verdict is the `valid` field of the body. `200` means "answered — read `valid`";
> `400` means the request could not be read; `401`/`403` mean *you* may not use the endpoint and carry
> a `WWW-Authenticate` challenge; `404` means the suite is disabled on that realm; `429` means rate
> limited. Before this release a credential that failed to verify was a bare `401` with no challenge,
> which RFC 9110 §15.5.2 forbids. **If you have a client that branches on the status rather than on
> `valid`, change it.**

### 9e. The rest of the settings

Every setting is read from the provider's configuration first, then a system property, then an
environment variable, then a compiled-in default — so the environment variables in the unit file below
need no `kc.sh build`. (A provider option belongs in `keycloak.conf` or on `kc.sh start`, never on
`kc.sh build`; see the note in [step 9d](#9d-decide-who-may-call-verify).)

| Setting | Environment variable | System property | Provider option | Default |
|---|---|---|---|---|
| Serve this suite at all | `LWS_AUTHN_ENABLED` | `lws.authn.enabled` | `enabled` | `true` |
| Audience to require when the request names none | `LWS_AUTHN_AUDIENCE` | `lws.authn.audience` | `audience` | — |
| `Cache-Control: max-age` on a served CID | `LWS_AUTHN_CID_CACHE_SECONDS` | `lws.authn.cid.cacheSeconds` | `cid-cache-seconds` | `300` |
| CID requests per minute, per caller | `LWS_AUTHN_CID_RATE_LIMIT` | `lws.authn.cid.rateLimit` | `cid-rate-limit` | `600` |
| Outbound fetch timeout (ms) | `LWS_AUTHN_HTTP_TIMEOUT_MILLIS` | `lws.authn.http.timeoutMillis` | `http-timeout-millis` | `5000` |
| Outbound response cap (bytes) | `LWS_AUTHN_HTTP_MAX_RESPONSE_BYTES` | `lws.authn.http.maxResponseBytes` | `http-max-response-bytes` | `262144` |
| Outbound fetch deadline, whole exchange (ms) | `LWS_AUTHN_HTTP_DEADLINE_MILLIS` | `lws.authn.http.deadlineMillis` | `http-deadline-millis` | `10000` |
| Outbound fetches one caller may have in flight | `LWS_AUTHN_HTTP_MAX_CONCURRENT_PER_CALLER` | `lws.authn.http.maxConcurrentPerCaller` | `http-max-concurrent-per-caller` | `4` |
| Clock skew on `exp`/`nbf`/`<Conditions>` (s) | `LWS_AUTHN_CLOCK_SKEW_SECONDS` | `lws.authn.clockSkewSeconds` | `clock-skew-seconds` | `60` |

The last five are server-wide: set them on any one provider and all three use them. Out-of-range
values are clamped rather than honoured.

**Turning a suite off.** `LWS_AUTHN_ENABLED=false` makes the suites' endpoints answer `404`. For just
one, `--spi-realm-restapi-extension--lws-saml--enabled=false` — the one provider option that *is*
build-time, so it goes on `kc.sh build`, and Keycloak then does not load that provider at all. For one realm only, set the realm attribute
`lws.authn.<providerId>.enabled` — for example:

```bash
kcadm.sh update realms/myrealm -s 'attributes."lws.authn.lws-saml.enabled"=false'
```

> In `bearer` and `secret` mode the `Authorization` header carries the **caller's** credential, so the
> credential being verified must be sent as the `credential` form parameter. Only `public` mode keeps
> the old fallback of reading the credential out of `Authorization`.

---

## 10. Build the optimized image

Whenever you add/remove a provider JAR or change a build-time option (`db`, `health-enabled`, …), run
`kc.sh build`. Do it as the `keycloak` user so it can write into the install directory:

```bash
sudo -u keycloak /opt/keycloak/bin/kc.sh build
```

The output re-lists the registered providers — confirm the `lws`, `lws-ssi-cid` and `lws-saml`
resources and the `lws-webid-sub-mapper` mapper appear, exactly as in
[step 8](#8-smoke-test-in-dev-mode).

### 9f. Make user attributes admin-only (do not skip this)

Two user attributes decide **who an identity is**:

| Attribute | What it does |
|---|---|
| `lws_jwk` | the public signing key published in the user's controlled identifier document — whoever holds the matching private key can sign credentials as that identity |
| the WebID attribute (whatever you name it in the mapper, if you use one) | becomes the `sub` claim of every ID Token for that user |

**A user who can write either one can become somebody else.** Setting their own `lws_jwk` lets them
mint self-signed credentials for their own WebID; setting their own WebID attribute makes Keycloak
issue an ID Token whose `sub` is an identifier they chose. Neither is a bug in this provider — it is
Keycloak faithfully issuing what the account says — which is exactly why the policy has to be right.

Keycloak 26 drops attributes that are not declared, so you have to allow them explicitly. Allow them
as **`ADMIN_EDIT`**, never `ENABLED`: `ENABLED` means the end user can write them from the account
console.

```bash
# Per realm. Replace myrealm.
kcadm.sh get realms/myrealm \
  | jq '.unmanagedAttributePolicy="ADMIN_EDIT"' \
  | kcadm.sh update realms/myrealm -f -
```

Or in the console: *Realm settings → General → Unmanaged attributes → **Only administrators can
write***.

Verify it took, before you trust anything the realm issues:

```bash
kcadm.sh get realms/myrealm --fields unmanagedAttributePolicy
# {"unmanagedAttributePolicy" : "ADMIN_EDIT"}
```

The stricter alternative, if you would rather not allow unmanaged attributes at all, is to declare
each attribute in the realm's user profile with `permissions.edit` set to `["admin"]` only. That is
equivalent for this purpose and narrower in general.

> **You do not need this at all if you use neither suite's hosted identifiers** — that is, if you run
> only the SAML verifier, or verify only DID subjects (`did:key`, `did:web`), none of which host
> anything here. Everyone else needs it.

---

## 11. Run Keycloak as a systemd service

### 11a. Secrets file

Put secrets in a root-only environment file (not in `keycloak.conf`):

```bash
sudo install -d -m 750 -o keycloak -g keycloak /etc/keycloak
sudo tee /etc/keycloak/keycloak.env >/dev/null <<'EOF'
# Database password (maps to db-password)
KC_DB_PASSWORD=CHANGE_ME_DB

# LWS SSRF allow-list — see step 9c. Leave empty unless the server must
# dereference its own documents over a loopback/internal address.
LWS_AUTHN_ALLOWED_INTERNAL_HOSTS=

# Who may call the LWS /verify endpoints — see step 9d. 'bearer' (the default)
# requires a Keycloak access token for the realm. Set 'public' only if the
# endpoints are already restricted to a trusted network.
LWS_AUTHN_VERIFY_ACCESS=bearer
LWS_AUTHN_VERIFY_RATE_LIMIT=60

# Optional, see step 9e. Uncomment to bind every verified credential to this
# server even when the caller forgets the 'audience' parameter, or to turn a
# suite off entirely.
#LWS_AUTHN_AUDIENCE=https://id.example.com/realms/myrealm
#LWS_AUTHN_ENABLED=true

# First boot ONLY: seed the temporary admin, then comment these out and
# restart (see step 11c).
KC_BOOTSTRAP_ADMIN_USERNAME=admin
KC_BOOTSTRAP_ADMIN_PASSWORD=CHANGE_ME_ADMIN
EOF
sudo chmod 600 /etc/keycloak/keycloak.env
```

> `KC_DB_PASSWORD` is Keycloak's environment-variable form of the `db-password` option (uppercase,
> `KC_` prefix, dashes → underscores). Every `LWS_AUTHN_*` setting is read directly by the provider,
> so they all take effect on restart with no `kc.sh build`.

### 11b. Unit file

Create `/etc/systemd/system/keycloak.service`:

```ini
[Unit]
Description=Keycloak (with lws-authn LWS provider)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
User=keycloak
Group=keycloak
EnvironmentFile=/etc/keycloak/keycloak.env
# Pin JAVA_HOME ONLY if you installed a dedicated JDK 21 in step 3:
# Environment=JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ExecStart=/opt/keycloak/bin/kc.sh start --optimized
Restart=on-failure
RestartSec=5
LimitNOFILE=102400
TimeoutStartSec=600

[Install]
WantedBy=multi-user.target
```

`start --optimized` skips the auto-build and boots straight from the image you produced in
[step 10](#10-build-the-optimized-image) — the correct, fast production start.

### 11c. Start it

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now keycloak
sudo systemctl status keycloak --no-pager
sudo journalctl -u keycloak -f          # follow the startup log
```

Once it's up, log in to the admin console at `https://id.example.com/admin/` (after
[step 12](#12-terminate-tls-with-nginx--certbot)) with the bootstrap credentials, create a
**permanent** admin user under the *master* realm, then **remove the two `KC_BOOTSTRAP_ADMIN_*`
lines** from `/etc/keycloak/keycloak.env` and `sudo systemctl restart keycloak`. The bootstrap
account is meant to be temporary.

---

## 12. Terminate TLS with nginx + certbot

Run nginx in front of Keycloak to handle HTTPS. Keycloak listens on `127.0.0.1:8080`; nginx serves
`443` and forwards the `X-Forwarded-*` headers that `proxy-headers=xforwarded` tells Keycloak to
trust.

```bash
sudo apt install -y nginx
```

Create `/etc/nginx/sites-available/keycloak`:

```nginx
server {
    listen 80;
    server_name id.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host  $host;
        proxy_set_header X-Forwarded-Port  $server_port;
    }
}
```

`X-Forwarded-For` is **overwritten** with the address nginx sees, not appended to with
`$proxy_add_x_forwarded_for`. Appending keeps whatever the client sent at the front of the list, and
that is the entry Keycloak reports as the caller's address — the one the verify and CID rate limits
bucket on. A client could then name a fresh address on every request. (If another proxy or a load
balancer sits in front of nginx, use its `real_ip` module to recover the client address instead, and
list that hop in `proxy-trusted-addresses` too.)

Enable it and obtain a certificate (certbot rewrites the block for HTTPS and adds an HTTP→HTTPS
redirect):

```bash
sudo ln -s /etc/nginx/sites-available/keycloak /etc/nginx/sites-enabled/keycloak
sudo nginx -t && sudo systemctl reload nginx

sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d id.example.com
```

Lock the firewall down to the proxy (keep `8080` internal):

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'      # 80 + 443
sudo ufw enable
```

Confirm discovery is served over your public hostname:

```bash
curl -s https://id.example.com/realms/master/.well-known/openid-configuration | jq .issuer
# -> "https://id.example.com/realms/master"
```

---

## 13. Verify the OpenID Connect suite end-to-end

This proves the `lws-oidc` suite works: a user's `sub` becomes a dereferenceable WebID, and the
credential passes the provider's `/verify` endpoint (the same algorithm an LWS server runs).

### Fast path — the bundled demo script

The repo ships a script that idempotently provisions a realm (`lws-demo`), a client (`lws-app`), the
**LWS WebID Subject** mapper, and a user (`alice`) holding the `lws-verifier` role, then obtains an ID
Token, dereferences the WebID, and runs it through `/verify`:

```bash
cd /tmp/lws-authn      # your clone from step 6
KC_URL=https://id.example.com \
ADMIN_USER=admin ADMIN_PASS=CHANGE_ME_ADMIN \
PASSWORD="$(openssl rand -base64 18)" \
bash scripts/lws-demo.sh
```

A successful run ends with **`valid: true`** and prints the WebID — that is a working LWS identity
issued by your server.

`PASSWORD` is required against anything but `localhost`: without it the user's password would be
`alice`, on an internet-facing server, for a user who may call `/verify`. The script's `lws-app` client
allows only the password grant, with no redirect URIs. **When you are done, delete the realm** —
*Realm settings → Action → Delete*, or
`kcadm.sh delete realms/lws-demo` — so neither the test user nor the demo client outlives the test. A
realm created by an earlier version of the script has a client with `redirectUris: ["*"]`, an
authorization-code theft vector; delete that one in any case.

### Manual path

1. In the admin console, **create realm** `lws-demo`.
2. **Clients → Create** `lws-app` (OpenID Connect). Enable *Direct access grants* so you can fetch a
   token by script (turn it off for real apps — use the Authorization Code flow).
3. **Clients → lws-app → Client scopes → `lws-app-dedicated` → Add mapper → By configuration → LWS
   WebID Subject.** Leave *WebID user attribute* blank (Keycloak hosts the WebID).
4. **Users → Create** `alice`; under **Credentials** set a non-temporary password.
5. Fetch a token and verify:

```bash
BASE=https://id.example.com/realms/lws-demo

TOKENS=$(curl -s -X POST "$BASE/protocol/openid-connect/token" \
  -d grant_type=password -d client_id=lws-app -d scope=openid \
  -d username=alice -d password=CHANGE_ME)
ID_TOKEN=$(echo "$TOKENS" | jq -r .id_token)          # the credential to verify
CALLER=$(echo "$TOKENS" | jq -r .access_token)        # who is asking (see step 9d)

# The sub is a WebID (a fetchable URL), not an opaque UUID:
echo "$ID_TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '{sub, iss}'

# Run the full validation (dereference sub -> locate OpenIdProvider service -> OIDC discovery -> verify signature):
curl -s -X POST "$BASE/lws/verify" \
  -H "Authorization: Bearer $CALLER" \
  --data-urlencode "credential=$ID_TOKEN" | jq
```

Expect:

```json
{
  "valid": true,
  "subject": "https://id.example.com/realms/lws-demo/lws/cid/…",
  "issuer":  "https://id.example.com/realms/lws-demo",
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

A failed verification also carries a `traceId`. The response deliberately says only *what* failed —
never an upstream status code, a resolved address or an exception message — so the detail is in the
server log at `DEBUG` under that id:

```bash
sudo journalctl -u keycloak | grep <traceId>
```

If `subjectDereferenced` is `false`, the server couldn't fetch its own WebID — revisit the hostname
([step 9b](#9b-write-keycloakconf)) and the SSRF allow-list ([step 9c](#9c-plan-the-ssrf-allow-list-important-for-openid-verify)).

---

## 14. Production checklist

- **Hostname** — `hostname=https://id.example.com` is set and publicly resolvable, so WebIDs and
  discovery are stable and dereferenceable.
- **HTTPS everywhere** — TLS terminated at nginx (or Keycloak directly); HTTP→HTTPS redirect on.
- **Database** — PostgreSQL, not H2; the DB password lives only in the root-only env file.
- **Bootstrap admin removed** — a permanent admin exists; `KC_BOOTSTRAP_ADMIN_*` deleted from the env
  file.
- **SSRF allow-list** — empty unless the server must dereference its own documents over an internal
  address, in which case it lists exactly those hosts.
- **`/verify` access** — left at `bearer`, or set to `public` only behind a network restriction that
  makes it unreachable from the internet ([step 9d](#9d-decide-who-may-call-verify)). In `bearer` mode
  the `lws-verifier` role exists and is held only by the services that verify credentials.
- **Settings in force** — the startup log's `lws-authn provider '…' settings in force` and `lws-authn
  server-wide settings in force` lines show the access mode, role, audience and allow-list you meant.
  A provider option passed to `kc.sh build` instead of `kc.sh start` is silently absent from them.
- **User attributes are admin-only** — the realm's unmanaged attribute policy is `ADMIN_EDIT`, not
  `ENABLED` ([step 9f](#9f-make-user-attributes-admin-only-do-not-skip-this)). `lws_jwk` is the signing
  key an identity publishes and the WebID attribute becomes a credential's `sub`; a user who can write
  either can impersonate an identity. Check it with
  `kcadm.sh get realms/<realm> --fields unmanagedAttributePolicy`.
- **Firewall** — only `22/80/443` exposed; Keycloak's `8080` stays on loopback.
- **Demo realm gone** — the `lws-demo` realm from [step 13](#13-verify-the-openid-connect-suite-end-to-end)
  is deleted, along with its test user and its demo client.
- **Direct Access Grants off** for real clients (it's on in the demo only to make it scriptable).
- **Audience** — if your LWS/resource server checks `aud`, add a Keycloak **Audience** mapper or use
  Resource Indicators (RFC 8707) / Token Exchange (RFC 8693, token type
  `urn:ietf:params:oauth:token-type:id_token`).
- **Backups** — back up the PostgreSQL database and `/opt/keycloak/conf/`.

---

## 15. Troubleshooting

| Symptom | Likely cause & fix |
|---------|--------------------|
| LWS providers not listed after `kc.sh build` | JAR not in `/opt/keycloak/providers/` or not owned by `keycloak`. Re-copy (step 7) and rebuild (step 10). |
| Service won't start; JVM/JDK error in the log | "Latest Java" isn't accepted by Keycloak 26. Install OpenJDK 21 (step 3) and set `JAVA_HOME` in the unit (step 11b). |
| `kc.sh` complains about H2/dev at startup | `start --optimized` ran but a build-time option changed. Re-run `kc.sh build` (step 10), then restart. |
| WebID / discovery URLs use the wrong host or `http` | `hostname` unset/wrong, or nginx isn't forwarding `X-Forwarded-*`. Fix `keycloak.conf` (step 9b) and the proxy headers (step 12); rebuild if needed. |
| `/lws/verify` → `subjectDereferenced: false` or a blocked-host error | The server can't reach its own WebID, or the SSRF guard blocked an internal address. Ensure the public hostname is reachable from the box, or set `LWS_AUTHN_ALLOWED_INTERNAL_HOSTS` (step 9c/11a) and restart. |
| `/verify` → `401` with `{"error":"invalid_token"}` and a `WWW-Authenticate` header | The **caller** is not authenticated. Since the endpoints are gated by default, pass your own access token in `Authorization` and the credential under test in the `credential` form field (step 9d). |
| `/verify` → `200` with `"valid": false` | The request was fine; the **credential** did not verify. Read `checks` and `errors` in the body, and the server log at `DEBUG` under the response's `traceId`. This used to be a `401` — see step 9d. |
| `/verify` or `/cid/{userId}` → `404` with `{"error":"not_found"}` | Either that user id does not exist, or the suite is disabled — check `LWS_AUTHN_ENABLED` and the realm attribute `lws.authn.<providerId>.enabled` (step 9e). |
| `/cid/{userId}` → `429` with `{"error":"slow_down"}` | The caller exceeded `LWS_AUTHN_CID_RATE_LIMIT` (default 600/minute, per source address). Raise it, or set it to `0` to disable. |
| `/verify` → `429` with `{"error":"slow_down"}` | The caller exceeded `LWS_AUTHN_VERIFY_RATE_LIMIT` (default 60/minute, per source address — IPv6 by `/64` — and in `bearer` mode per user as well). Raise it, or set it to `0` to disable rate limiting. If every caller is limited together, Keycloak is seeing the proxy's address: check `proxy-headers` and `proxy-trusted-addresses` (steps 9b and 12). |
| `directAccessGrantsEnabled`/token request returns `invalid_client` | The client isn't public or Direct Access Grants is off. For the demo client, enable both. |

Useful commands:

```bash
sudo journalctl -u keycloak -f                       # live logs
sudo -u keycloak /opt/keycloak/bin/kc.sh show-config # effective configuration
curl -s https://id.example.com/health/ready          # readiness (health-enabled=true)
```

---

## 16. Upgrading & uninstalling

**Upgrade the provider JAR** (same Keycloak version): rebuild the JAR (step 6), replace it in
`providers/`, then:

```bash
sudo -u keycloak /opt/keycloak/bin/kc.sh build
sudo systemctl restart keycloak
```

**Upgrade Keycloak itself.** A patch release of the same minor (26.8.0 → 26.8.1) needs no new provider
build: install the new distribution (step 5), re-point the `/opt/keycloak` symlink, redeploy the same
JAR (step 7), `kc.sh build`, restart. Take these as they come — they are where Keycloak's security
fixes land. A new minor (26.9) needs the provider rebuilt against it: bump `keycloak.version` in
`pom.xml`, rebuild (step 6), then as above.

### Upgrading a deployment that predates the October 2026 review

A server running a provider built before the fixes in [the changelog](CHANGELOG.md)'s *Security*
section will see breaking changes, and most of them surface as `401`, `403` or `valid: false` on
traffic that works today. Prepare, then deploy in two steps.

**Before deploying**

1. **Audit what your issuers send.** The claim-level checks have no opt-out: `azp`, `iat` and `kid` are
   required; a controlled identifier document needs `id`, `type` and `controller`; `revoked`/`expires`
   that are not one date make a key unusable; and `sub`, `iss` and `jwks_uri` must be `https` unless
   their host is on the SSRF allow-list. Run a sample of real credentials through a test server first.
2. **Create the `lws-verifier` realm role** in every realm that serves `/verify`, and grant it to every
   caller — normally the authorization server's service account ([step 9d](#9d-decide-who-may-call-verify)).
3. **Callers send the credential in the `credential` form field** and their own access token in
   `Authorization`, which no longer means "the credential to verify" outside `public` mode.
4. **Move any provider option off `kc.sh build`** into `keycloak.conf` or the environment
   ([step 9d](#9d-decide-who-may-call-verify)).
5. **Fix the proxy headers**: nginx sets `X-Forwarded-For $remote_addr`, and `keycloak.conf` has
   `proxy-trusted-addresses` ([steps 9b](#9b-write-keycloakconf) and [12](#12-terminate-tls-with-nginx--certbot)).
6. **Run Keycloak 26.8.0 or a later 26.8 release** — the minor this provider is built against. From 26.7
   that is a minor upgrade: stop every node, back up the database, and read Keycloak's
   [migration notes](https://www.keycloak.org/docs/latest/upgrading/) first.

**Deploy, then tighten**

7. Deploy the new JAR with `LWS_AUTHN_VERIFY_ACCESS=public` in `/etc/keycloak/keycloak.env`, so callers
   that have not yet switched to step 3 keep working while you check. On an internet-facing server keep
   this window short, or restrict `…/verify` in nginx to your callers' addresses while it lasts.
   Restart, read the `settings in force` lines in the startup log, and run a known-good credential
   through each suite you use; anything `valid: false` lists the failed check.
8. Remove `LWS_AUTHN_VERIFY_ACCESS` (back to `bearer`), restart, and confirm your callers get `200`s —
   a `401` means a caller without an access token, a `403` one without the role.
9. Delete any `lws-demo` realm the [fast path](#fast-path--the-bundled-demo-script) created on this server.

**Uninstall**:

```bash
sudo systemctl disable --now keycloak
sudo rm /etc/systemd/system/keycloak.service && sudo systemctl daemon-reload
sudo rm -rf /opt/keycloak /opt/keycloak-${KC_VERSION} /etc/keycloak
# Optionally drop the database:
sudo -u postgres psql -c "DROP DATABASE keycloak;" -c "DROP USER keycloak;"
```

---

### Reference

- Provider documentation, per-suite walkthroughs, and demo scripts: [this site](index.md),
  [the walkthroughs](walkthroughs.md), [`scripts/`](https://github.com/ebremer/lws-authn/tree/master/scripts).
- LWS OpenID Connect authentication spec:
  <https://w3c.github.io/lws-protocol/lws10-authn-openid/>.
