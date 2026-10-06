/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reads the shaded provider JAR the build produced and checks what is in it. No Docker needed: it runs
 * in `mvn verify` wherever the JAR was built.
 */
package com.ebremer.lws.authn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.jar.JarFile;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * What may be bundled unrelocated in the provider JAR (R-42).
 *
 * <p>A library Keycloak also ships, bundled under its own package names, puts a second copy of that
 * package on the server's classpath; until R-42 that was true of Gson, commons-io (an older copy) and
 * commons-lang3, and nothing failed. The enforcer's {@code banDuplicateClasses} cannot see it, because
 * it ignores the {@code provided} scope where Keycloak's copies are. So this reads the JAR itself: every
 * class is either this provider's own (relocated libraries included) or in a package the server does
 * not have. A new transitive dependency of Jena lands here first, and has to be relocated, made
 * {@code provided}, or added below with the reason.</p>
 */
class ShadedJarContentsIT {

    /** Packages bundled as they are, none of which the Keycloak 26.8.0 server has on its runtime classpath. */
    private static final List<String> UNRELOCATED = List.of(
            "com/ebremer/lws/authn/",          // this provider, and everything relocated under .shaded
            "org/apache/jena/",
            "org/apache/thrift/",              // Jena's RIOT registry needs it; Keycloak has none
            "org/roaringbitmap/",
            "com/github/andrewoma/dexx/",
            "org/apache/commons/compress/",    // Keycloak has it at build time (lib/deployment) only
            "org/apache/commons/csv/");

    /** One class from each library relocated under {@code com.ebremer.lws.authn.shaded}. */
    private static final List<String> RELOCATED = List.of(
            "com/ebremer/lws/authn/shaded/gson/Gson.class",
            "com/ebremer/lws/authn/shaded/commons/io/IOUtils.class",
            "com/ebremer/lws/authn/shaded/commons/lang3/StringUtils.class",
            "com/ebremer/lws/authn/shaded/commons/codec/binary/Hex.class",
            "com/ebremer/lws/authn/shaded/commons/collections4/CollectionUtils.class",
            "com/ebremer/lws/authn/shaded/caffeine/cache/Caffeine.class",
            "com/ebremer/lws/authn/shaded/apicatalog/jsonld/JsonLd.class");

    @Test
    void everyClassIsOursOrInAPackageTheServerDoesNotHave() throws IOException {
        Set<String> strays = new TreeSet<>();
        try (JarFile jar = new JarFile(providerJar().toFile())) {
            jar.stream()
                    .map(entry -> entry.getName())
                    .filter(name -> name.endsWith(".class"))
                    // A multi-release class is the same class: judge it by its package.
                    .map(name -> name.replaceFirst("^META-INF/versions/\\d+/", ""))
                    .filter(name -> !name.equals("module-info.class"))
                    .filter(name -> UNRELOCATED.stream().noneMatch(name::startsWith))
                    .forEach(name -> strays.add(name.substring(0, Math.max(0, name.lastIndexOf('/')))));
        }
        assertTrue(strays.isEmpty(), "bundled unrelocated, and not on the list of packages Keycloak lacks: "
                + strays + " — relocate it in the shade plugin, make it provided, or add it to UNRELOCATED");
    }

    @Test
    void theRelocatedLibrariesAreThere() throws IOException {
        try (JarFile jar = new JarFile(providerJar().toFile())) {
            for (String name : RELOCATED) {
                assertTrue(jar.getEntry(name) != null, "missing from the JAR: " + name);
            }
        }
    }

    /**
     * The SBOM describes the JAR, not the build (R-45): none of the server's libraries, nothing from the
     * test tree. It used to list 208 components, about 180 of them Keycloak's, so a scanner would have
     * attributed Keycloak's advisories to this JAR. CycloneDX does not run offline, so neither does this.
     */
    @Test
    void theSbomListsOnlyWhatIsBundled() throws IOException {
        Path bom = providerJar().resolveSibling("bom.json");
        Assumptions.assumeTrue(Files.exists(bom), "no target/bom.json: the CycloneDX plugin does not run offline");
        Set<String> notBundled = Set.of("org.keycloak", "io.quarkus", "org.slf4j", "org.glassfish",
                "com.google.protobuf", "org.jspecify", "com.google.errorprone", "org.junit.jupiter",
                "org.testcontainers", "com.github.dasniko", "org.bouncycastle", "org.apache.httpcomponents",
                "org.jboss.logging", "jakarta.ws.rs");
        Set<String> listed = new TreeSet<>();
        for (JsonNode component : new ObjectMapper().readTree(bom.toFile()).path("components")) {
            String group = component.path("group").asText();
            listed.add(group + ":" + component.path("name").asText());
            assertTrue(!notBundled.contains(group), "the SBOM lists " + group + ":" + component.path("name").asText()
                    + ", which the JAR does not contain");
            assertEquals("required", component.path("scope").asText(), "scope of " + group);
        }
        assertTrue(listed.contains("org.apache.jena:jena-arq") && listed.contains("com.google.code.gson:gson"),
                "the SBOM does not list what is bundled: " + listed);
    }

    /** The JAR Failsafe names, or the newest one in {@code target/} when run from an IDE. */
    static Path providerJar() throws IOException {
        String configured = System.getProperty("lws.authn.providerJar");
        if (configured != null && !configured.isBlank()) {
            return Path.of(configured);
        }
        try (var jars = Files.newDirectoryStream(Path.of("target"), "lws-authn-*.jar")) {
            Path newest = null;
            for (Path jar : jars) {
                if (newest == null || Files.getLastModifiedTime(jar).compareTo(Files.getLastModifiedTime(newest)) > 0) {
                    newest = jar;
                }
            }
            if (newest == null) {
                throw new IllegalStateException("no target/lws-authn-*.jar; run `mvn package` first");
            }
            return newest;
        }
    }
}
