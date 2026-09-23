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

ARG KEYCLOAK_VERSION=26.7.4

# ── 1. Build the shaded provider JAR ────────────────────────────────────────────────────────────
# JDK 21: the release the class files target, and the one CI builds and tests with.
FROM maven:3.9-eclipse-temurin-21 AS provider
WORKDIR /src
# The POM on its own first, so the dependency download is a cached layer that a source edit does not
# invalidate.
COPY pom.xml .
RUN mvn -B -ntp -q dependency:go-offline
COPY src src
# Tests are skipped: the unit tests are CI's job, and LwsAuthIT needs a Docker daemon of its own.
RUN mvn -B -ntp -q -DskipTests package \
 && cp target/lws-authn-*.jar /lws-authn.jar

# ── 2. Keycloak with the provider ───────────────────────────────────────────────────────────────
FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}
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
