# Copyright Erich Bremer.
#
# SPDX-License-Identifier: Apache-2.0
#
# A Keycloak image with the lws-authn provider built in, for trying the suites locally. It is a
# development image — `compose.yaml` runs it with `start-dev`, the in-memory database and a bootstrap
# admin — not a production one; for that, follow docs/INSTALL.md.
#
#   docker compose up --build --wait      # build, start, and wait until Keycloak is ready
#
# The provider is built from this checkout, so the image always carries the code beside it.
#
# Both base images are pinned by digest as well as tag (R-47): a tag can be moved to any image at any
# time, and the digest is what makes the build reproducible and reviewable. Dependabot proposes digest
# updates (.github/dependabot.yml). The Keycloak tag is the POM's keycloak.version, which
# KeycloakVersionPinsTest checks; when it moves, the digest moves with it:
#   curl -sI -H 'Accept: application/vnd.oci.image.index.v1+json' \
#     https://quay.io/v2/keycloak/keycloak/manifests/<version> | grep -i docker-content-digest

# ── 1. Build the shaded provider JAR ────────────────────────────────────────────────────────────
# JDK 21: the release the class files target, and the one CI builds and tests with.
FROM maven:3.9-eclipse-temurin-21@sha256:99e61abcff91a9b1333463bd8451fb18495d6eba9250ac66a338b518f8278320 AS provider
WORKDIR /src
# The POM on its own first, so the dependency download is a cached layer that a source edit does not
# invalidate.
COPY pom.xml .
RUN mvn -B -ntp -q dependency:go-offline
# The JAR's licence is read from this file at packaging time; the build fails without it (R-46).
COPY LICENSE .
COPY src src
# Tests are skipped: the unit tests are CI's job, and LwsAuthIT needs a Docker daemon of its own.
RUN mvn -B -ntp -q -DskipTests package \
 && cp target/lws-authn-*.jar /lws-authn.jar

# ── 2. Keycloak with the provider ───────────────────────────────────────────────────────────────
FROM quay.io/keycloak/keycloak:26.8.0@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc
COPY --from=provider /lws-authn.jar /opt/keycloak/providers/lws-authn.jar
# The demo realm, imported on first start by `--import-realm`.
COPY examples/lws-demo-realm.json /opt/keycloak/data/import/lws-demo-realm.json
# Health endpoints (management port 9000) are a build-time option; compose's healthcheck uses them.
ENV KC_HEALTH_ENABLED=true
# Registers the provider at image build time, so a broken JAR fails `docker build` rather than the
# first start. `start-dev` re-augments anyway, but finds nothing to change.
RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start-dev", "--import-realm"]
