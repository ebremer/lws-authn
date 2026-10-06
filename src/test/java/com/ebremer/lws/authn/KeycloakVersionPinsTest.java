/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * R-14. The Keycloak release is named in the POM, and two places that cannot read the POM repeat it:
 * the {@code Dockerfile}'s default and {@code LwsAuthIT}'s fallback image. A Keycloak upgrade that
 * misses one of them builds the Docker demo, or runs the integration test outside Failsafe, against
 * the old release — the one the upgrade was for. This fails the build instead.
 */
class KeycloakVersionPinsTest {

    private static String find(Path file, String regex) throws IOException {
        Matcher m = Pattern.compile(regex).matcher(Files.readString(file));
        assertTrue(m.find(), file + " no longer matches " + regex);
        return m.group(1);
    }

    @Test
    void theDockerfileAndTheIntegrationTestUseThePomsKeycloak() throws IOException {
        String pom = find(Path.of("pom.xml"), "<keycloak\\.version>([^<]+)</keycloak\\.version>");
        assertEquals(pom, find(Path.of("Dockerfile"), "ARG KEYCLOAK_VERSION=(\\S+)"), "Dockerfile");
        assertEquals(pom, find(Path.of("src/test/java/com/ebremer/lws/authn/LwsAuthIT.java"),
                "\"quay\\.io/keycloak/keycloak:([^\"]+)\""), "LwsAuthIT's fallback image");
    }
}
