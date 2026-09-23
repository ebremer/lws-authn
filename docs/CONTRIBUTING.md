# Contributing

Thanks for looking. This is a small project with a specific job: implement the W3C Linked Web
Storage authentication suites as Keycloak providers, correctly enough that the answer to "is this
credential genuine" can be relied on.

**Security issues do not go here.** See [`SECURITY.md`](SECURITY.md) — email, not an issue.

## Getting set up

Requires **JDK 21+** and Maven; Docker for the integration test.

```bash
mvn clean verify      # 179 unit tests + 24 in LwsAuthIT (a real Keycloak 26.7.4 container)
mvn clean test        # unit tests only, no Docker needed
```

`LwsAuthIT` **binds host port 8080 and cannot run in parallel with itself** — the OpenID verifier
dereferences its own issuer, so that URL has to resolve to Keycloak from both the test JVM and inside
the container. The suite checks the port first and tells you if something else holds it; the full
reasoning is in the `LwsAuthIT` class javadoc.

## What this codebase expects

Read a neighbouring file before writing a new one. The conventions that matter:

**Comments say *why*, and cite the reason.** A comment that restates the code is noise; a comment that
names the specification clause, the attack, or the alternative that was rejected is the reason the
next person can change the code safely. Most non-obvious lines here cite an RFC section, a suite
requirement, or a `TODO.md` item id.

**Prefer a function that cannot be called wrongly over a rule to remember.** `JsonResponses` exists
because "remember to escape the JSON" is not a control; `KeyIdFragment` exists because "remember to
encode the `kid`" is not either.

**Verifiers fail closed.** Any unexpected condition means "not valid", never "valid". If you add a
check, add it as `result.check("someName", ok)` so the caller can see which one failed, and return
`result.fail()` rather than continuing.

**Never reflect internal detail to a caller.** No upstream status codes, resolved addresses or
exception text in a response. Log it at `DEBUG` under the result's `traceId`.

## Layout

```
src/main/java/com/ebremer/lws/authn/
  config/                                       configuration surface
    Settings                                    scope -> system property -> environment -> default
    ServerSettings                              server-wide tunables (SSRF list, timeouts, skew)
    EndpointSettings                            per-provider settings, incl. the per-realm on/off flag
  did/                                          DID subjects, shared by the self-signed suites
    Dids                                        DID syntax, did:key expansion, did:web URL mapping
    DidKey                                      multibase/multicodec codec (did:key, Multikey), pure JDK
  http/                                         shared endpoint plumbing
    JsonResponses                               every non-result body, serialized not concatenated
    CidEndpoint                                 the shared cid/{userId} endpoint
  openid/                                       OpenID Connect suite
    LWSConstants, LWSSubMapper                  vocabulary + sub→WebID protocol mapper
    cid/ControlledIdentifierDocument            CID builder (OpenIdProvider service)
    resource/LWSResourceProvider(.Factory)      JAX-RS endpoints, mount id "lws"
    verify/LWSCredentialVerifier, VerificationResult
  ssicid/                                       Self-signed CID suite
    SsiCidConstants
    cid/SelfSignedControlledIdentifierDocument  CID builder (publicKeyJwk methods)
    resource/SsiCidResourceProvider(.Factory)   mount id "lws-ssi-cid"
    verify/SelfSignedCidVerifier, SsiCidVerificationResult
  saml/                                         SAML 2.0 suite
    SamlConstants
    resource/SamlResourceProvider(.Factory)     mount id "lws-saml"
    verify/SamlCredentialVerifier, SamlVerificationResult
src/main/resources/META-INF/services/           SPI registrations (mapper + three resource factories)
```

## Tests

**A new rule needs a negative test.** That is the whole point: a verifier that wrongly rejects gets
reported by its users, and one that wrongly accepts does not. Assert *which check* failed, not merely
that the credential was refused — an assertion that only looks at `valid: false` keeps passing after
the branch it was written for stops being reachable.

Where to put it:

| The behaviour is decided… | Test it in |
|---|---|
| before anything is dereferenced (claims, headers, document shape) | a unit test — fast, no Docker |
| after an outbound fetch (discovery, JWKS, key selection, signature) | `LwsAuthIT`, using the host-side fixture server |
| by the packaging (shading, relocation, the real classpath) | `LwsAuthIT` — nothing else can see it |

That last row is not a preference. Two real bugs were caught only by the container: Jena's Turtle
writer losing `commons-compress`, and no EC-signed credential verifying in any suite. Both were
invisible to unit tests by construction — one needed the real shaded classpath, the other Keycloak's
own crypto providers. **Run `mvn verify`, not just `mvn test`, after touching dependencies or
packaging.**

## Dependencies

The shaded JAR is a minefield and the build enforces the rules; read [Build](build.md#build) before
adding anything. In short: a library Keycloak already ships is either `provided` (use the server's) or
bundled **and relocated** (when Jena needs a newer one). Bundling an unrelocated second copy puts two
implementations of one package on the classpath. `maven-enforcer-plugin` fails the build on duplicate
classes, and `dependency:tree` shows only one path per artifact — use
`-Dincludes=<groupId>:<artifactId>` before concluding anything about why something is on the classpath.

## Documentation

The documentation is the website <https://ebremer.github.io/lws-authn/>, and its source is
[`docs/`](https://github.com/ebremer/lws-authn/tree/master/docs): Jekyll with the Just the Docs
theme, configured in `docs/_config.yml`. GitHub Pages builds it from `master` itself, so there is no
workflow to maintain. Each document exists once, as a page of the site; the README at the root is a
summary that links to it, and `TODO.md` stays beside it. The site is `docs/` and nothing else, which
has two consequences:

- **Link from one page to another with an ordinary relative link to its `.md` file**; the build rewrites
  it to the page. **Link to anything outside `docs/`** — source, scripts, `TODO.md`, `LICENSE` — by its
  absolute `https://github.com/ebremer/lws-authn/blob/master/…` URL: a relative `../` link works when
  browsing the repository and is a 404 on the site.
- **A new page needs front matter** — a `title` and a `nav_order`, plus a `parent` (`Walkthroughs` or
  `Reference`) to nest it. `SECURITY.md` and this file are the exceptions: GitHub also shows them on
  its own pages, so they carry no front matter, and their titles are in `docs/_config.yml`.

To preview a change, run `bundle install` and then `bundle exec jekyll serve` in `docs/`, and open
`http://localhost:4000/`. This needs Ruby 3 — GitHub builds with 3.3 — because the `github-pages` gem
does not install on Ruby 4.

## Commits and pull requests

- Work on a branch and open a pull request; `master` is not committed to directly.
- The subject line says what changed; the body says **why**, and names the `TODO.md` item if there is
  one. The existing log is the model — these messages are the project's design history.
- One logical change per commit.
- `mvn clean verify` must be green. CI additionally builds on JDK 25 and asserts the class files are
  still Java 21, runs CodeQL, and reviews dependency changes.
- New files need the SPDX header:

  ```java
  /*
   * Copyright Erich Bremer.
   *
   * SPDX-License-Identifier: Apache-2.0
   */
  ```

## The backlog

[`TODO.md`](https://github.com/ebremer/lws-authn/blob/master/TODO.md) is the real backlog, written as a review against the specifications: each item
names the file, states what the spec requires versus what the code does, and — once done — what was
actually changed and why. Completed items are kept rather than deleted, because the reasoning is the
useful part. If you are looking for something to do, the open items are marked `[ ]`.

By contributing you agree your contributions are licensed under Apache-2.0, matching
[`LICENSE`](https://github.com/ebremer/lws-authn/blob/master/LICENSE).
