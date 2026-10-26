/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

/**
 * R-53. Keycloak keeps a client's and a role's description in a 255-character column, and importing a
 * longer one fails the whole import: Keycloak exits at startup, so the demo realm takes
 * {@code docker compose up} and {@code LwsAuthIT} down with it. R-13 lengthened the demo client's
 * description to 268 characters, and CI failed on every run from then on. This catches it without
 * Docker.
 */
class DemoRealmTest {

    /** The width of Keycloak's description columns ({@code CLIENT.DESCRIPTION}, {@code KEYCLOAK_ROLE.DESCRIPTION}). */
    private static final int DESCRIPTION_COLUMN = 255;

    @Test
    void everyDescriptionFitsKeycloaksColumn() throws IOException {
        JsonNode realm = new ObjectMapper().readTree(Path.of("examples/lws-demo-realm.json").toFile());
        List<String> found = new ArrayList<>();
        List<String> tooLong = new ArrayList<>();
        collect(realm, "$", found, tooLong);
        assertTrue(found.size() >= 2, "expected the client's and the role's descriptions, found " + found);
        assertTrue(tooLong.isEmpty(), "longer than " + DESCRIPTION_COLUMN + " characters: " + tooLong);
    }

    private static void collect(JsonNode node, String path, List<String> found, List<String> tooLong) {
        if (node.isObject()) {
            for (var field : node.properties()) {
                String at = path + "." + field.getKey();
                if (field.getKey().equals("description") && field.getValue().isTextual()) {
                    found.add(at);
                    int length = field.getValue().asText().length();
                    if (length > DESCRIPTION_COLUMN) {
                        tooLong.add(at + " (" + length + ")");
                    }
                }
                collect(field.getValue(), at, found, tooLong);
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                collect(node.get(i), path + "[" + i + "]", found, tooLong);
            }
        }
    }
}
