---
title: Build and deploy
nav_order: 2
---

# Build and deploy

## Run with Docker

The quickest way to try the suites. [`compose.yaml`](https://github.com/ebremer/lws-authn/blob/master/compose.yaml)
builds the provider from your checkout into a Keycloak 26.7.4 image and starts it with a demo realm
already imported. It needs only Docker with Compose: no JDK, Maven or Keycloak install.

```bash
docker compose up --build --wait    # build and start; returns once Keycloak is ready
bash scripts/lws-demo.sh            # or any walkthrough
docker compose down                 # stop, and discard everything
```

Keycloak is at `http://localhost:8080`, and its admin console signs in as `admin` / `admin`. The
image's build skips the tests, so run `mvn verify` for those.

The realm is [`examples/lws-demo-realm.json`](https://github.com/ebremer/lws-authn/blob/master/examples/lws-demo-realm.json),
which is also what the walkthroughs import by hand:

| | |
|---|---|
| Realm | `lws-demo` |
| Client | `lws-app`: public, *Direct access grants* on, with the **LWS WebID Subject** mapper |
| User | `alice`, password `alice`, whose WebID is `http://localhost:8080/realms/lws-demo/lws/cid/fb147f85-59e9-4288-a907-38aa2d4a33b5` |
| User profile | Unmanaged attributes `ADMIN_EDIT`: an admin can set `lws_jwk`, the user cannot |

The demo scripts find all of this already in place and go straight to minting and verifying
credentials. The walkthroughs' defaults, `KC_URL=http://localhost:8080` and `admin` / `admin`, are this
container's.

After changing the code, run `docker compose up --build --wait` again. It rebuilds the image and
replaces the container, so the realm is imported afresh.

**To use another port**, set `KC_PORT` for both commands:

```bash
KC_PORT=8081 docker compose up --build --wait
KC_URL=http://localhost:8081 bash scripts/lws-demo.sh
```

Keycloak then listens on that port inside the container too, and it has to. The OpenID verifier
dereferences the credential's own issuer, `http://localhost:<port>/realms/lws-demo`, and inside the
container `localhost` is Keycloak itself. So the issuer URL works only if Keycloak listens on the
port the host sees.

**This is a development setup**, and differs from a deployment in ways that matter:

- `start-dev` serves plain HTTP and takes its hostname from each request.
- The database lives in the container. `docker compose stop` keeps it; `down` discards it.
- `LWS_AUTHN_ALLOWED_INTERNAL_HOSTS=localhost,127.0.0.1` opens the SSRF guard to loopback, which the
  self-dereference above needs. On a server anyone else can reach, that setting lets a credential
  point the verifier at the server's own internal services.
- The admin and `alice` have well-known passwords, and `lws-app` allows the password grant.

For a real server, follow the [install guide](INSTALL.md).

## Build

Requires JDK 21+ and Maven. (The build compiles to Java 21 bytecode so the provider loads in
Keycloak's runtime; a newer build JDK such as 25 is fine.)

```bash
mvn clean package
```

This produces a single, self-contained provider JAR: **`target/lws-authn-<version>.jar`** — this tree is
`0.3.0-SNAPSHOT`, unreleased work after 0.2.0 — plus a CycloneDX
SBOM (`target/bom.json`, `target/bom.xml`) listing exactly what is inside it and under what licence.

Apache Jena and its dependencies are shaded in. Where Jena and Keycloak want the same library, the
build picks one of two strategies deliberately, because the wrong one is a runtime failure either way:

| Situation | Treatment | Examples |
|---|---|---|
| An interface or facade whose Keycloak copy satisfies Jena | `provided` — use the server's, bundle nothing | `slf4j-api`, `jcl-over-slf4j`, `jakarta.json`, `jspecify` |
| A library carrying behaviour Jena depends on | bundle the version Jena declares and **relocate** it | `commons-codec` 1.22.0, `titanium-json-ld` 1.7.0, `commons-collections4` 4.5.0, `caffeine` 3.2.4 |

Bundling an unrelocated second copy of a library the server already has puts two implementations of one
package on the classpath; marking one `provided` when the server's copy is older silently downgrades
it — Keycloak 26.7.4 runs Titanium 1.3.3 and Caffeine 3.2.3 against Jena's 1.7.0 and 3.2.4. The bundled
versions are pinned explicitly, because Maven would otherwise resolve the older versions Keycloak's own
POMs declare (commons-codec 1.11, commons-collections4 4.4, Titanium 1.3.3, Caffeine 3.2.3). The shade
plugin's comment in `pom.xml` tabulates all three columns.

`mvn package` enforces this: `maven-enforcer-plugin` fails the build on duplicate classes among the
bundled artifacts, and the shade plugin's `artifactSet` excludes hold regardless of what Maven's scope
mediation decides. Keycloak's own SAML, crypto and HTTP libraries are `provided` — they are part of the
server runtime.

Getting this wrong does not fail a unit test: it fails when Jena loads inside Keycloak. `mvn verify`
runs `LwsAuthIT`, which deploys the shaded JAR into a real Keycloak container and exercises RDF
serving, parsing and SPARQL — run it after touching dependencies.

### Tests

`mvn test` runs 179 unit tests. `mvn verify` additionally runs 24 in `LwsAuthIT`, which needs Docker
and is skipped without it.

**`LwsAuthIT` binds host port 8080 and cannot run in parallel with itself.** The OpenID verifier
dereferences its own issuer, so that URL has to resolve to Keycloak both from the test JVM and from
inside the container, and `http://localhost:8080` bound straight through is the only spelling that
does. The suite checks the port first and says so rather than timing out; the reasoning, and why a
random port is not worth what it costs, is in the `LwsAuthIT` class javadoc.

Roughly half the integration tests assert a *rejection* rather than an acceptance. That is deliberate:
a verifier that wrongly rejects gets reported by its users, and one that wrongly accepts does not, so
the failure branches are where a bug goes unnoticed. A host-side fixture server plays a third-party
OpenID Provider — controlled identifier document, discovery document, JWKS — and each test breaks
exactly one of the three, asserting *which* check fails rather than merely that the credential was
refused.

CI (`.github/workflows/ci.yml`) runs that on JDK 21, builds again on JDK 25 and asserts the class files
are still Java 21, and runs CodeQL. Actions are pinned by commit SHA; Dependabot proposes the bumps.

## Deploy

Keycloak loads provider JARs from its `providers/` directory.

```bash
# from the project root, with $KC_HOME pointing at your Keycloak 26.7.4 install
cp target/lws-authn-*.jar "$KC_HOME/providers/"   # the one shaded JAR `mvn package` produced

"$KC_HOME/bin/kc.sh" build      # re-augment with the new provider
"$KC_HOME/bin/kc.sh" start      # or start-dev
```

On Windows use `kc.bat`. After `kc.sh build`, the startup log lists the registered providers; you
should see the `lws`, `lws-ssi-cid` and `lws-saml` realm resources and the `lws-webid-sub-mapper`
protocol mapper.

For a production server — service account, database, `systemd`, TLS and the rest — follow the
[install guide](INSTALL.md).
