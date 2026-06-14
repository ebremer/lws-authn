/*
 * Copyright Erich Bremer.
 *
 * Integration test: deploys the built provider JAR into a real Keycloak 26.7.0 via Testcontainers and
 * runs the same end-to-end smoke flow that was validated by hand — the mapper fires, all four suite
 * endpoints mount, shaded Jena serves/parses RDF, and the OpenID and did:key credentials verify.
 *
 * Requires Docker. Runs in `mvn verify` (failsafe, after the JAR is packaged) and is skipped
 * automatically when Docker is unavailable.
 */
package com.ebremer.lws.authn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.DockerClientFactory;

import com.ebremer.lws.authn.ssididkey.DidKey;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LwsAuthIT {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final String REALM = "lws-demo";
    private static final String IMAGE = "quay.io/keycloak/keycloak:26.7.0";
    private static final String PROVIDER_JAR = "target/lws-authn-0.1.0.jar";

    private KeycloakContainer keycloak;
    private String base; // http://localhost:8080

    @BeforeAll
    void startKeycloak() {
        Assumptions.assumeTrue(DockerClientFactory.instance().isDockerAvailable(),
                "Docker is required for the Testcontainers integration test");
        keycloak = new KeycloakContainer(IMAGE)
                .withProviderLibsFrom(List.of(new File(PROVIDER_JAR)))
                .withRealmImportFile("lws-demo-realm.json")
                // The OpenID verifier self-dereferences the realm issuer (a loopback URL here), so the
                // SSRF guard must be told that loopback is an intended target in this deployment.
                .withEnv("LWS_AUTHN_ALLOWED_INTERNAL_HOSTS", "localhost,127.0.0.1");
        // Pin to host port 8080 so the issuer URL (http://localhost:8080/...) resolves to Keycloak
        // BOTH from this test and from inside the container — the OpenID verifier dereferences its
        // own issuer, and a random mapped port would be unreachable from within the container.
        keycloak.setPortBindings(List.of("8080:8080"));
        keycloak.start();
        base = keycloak.getAuthServerUrl();
    }

    @AfterAll
    void stopKeycloak() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }

    // ----------------------------------------------------------------- the smoke flow as assertions

    /** The LWS WebID Subject mapper fires: the ID Token's sub is the Keycloak-hosted WebID. */
    @Test
    void mapperSetsSubjectToWebId() throws Exception {
        String sub = claim(idToken(), "sub");
        assertTrue(sub.startsWith(base + "/realms/" + REALM + "/lws/cid/"),
                "sub should be the Keycloak-hosted WebID, was: " + sub);
    }

    /** The OpenID CID endpoint mounts and serves RDF in multiple syntaxes (shaded Jena works). */
    @Test
    void cidServedAsTurtleAndJsonLd() throws Exception {
        String sub = claim(idToken(), "sub");
        String turtle = get(sub, "text/turtle");
        assertTrue(turtle.contains("https://www.w3.org/ns/lws#OpenIdProvider"), turtle);
        assertTrue(turtle.contains("https://www.w3.org/ns/did#serviceEndpoint"), turtle);
        String jsonld = get(sub, "application/ld+json");
        assertTrue(jsonld.contains("\"@context\""), jsonld);
        assertTrue(jsonld.contains("OpenIdProvider"), jsonld);
    }

    /** Full OpenID validation: dereference sub, locate service (Jena/SPARQL), discovery, signature. */
    @Test
    void openIdCredentialVerifies() throws Exception {
        JsonNode r = JSON.readTree(postForm(base + "/realms/" + REALM + "/lws/verify",
                Map.of("credential", idToken())).body());
        assertTrue(r.get("valid").asBoolean(), () -> "expected valid, got: " + r);
        r.get("checks").fields().forEachRemaining(e ->
                assertTrue(e.getValue().asBoolean(), "check failed: " + e.getKey()));
    }

    /** did:key suite: self-signed credentials verify for both P-256 and Ed25519. */
    @Test
    void didKeyCredentialsVerify() throws Exception {
        for (String jwt : List.of(mintDidKeyP256(), mintDidKeyEd25519())) {
            JsonNode r = JSON.readTree(postForm(base + "/realms/" + REALM + "/lws-ssi-did-key/verify",
                    Map.of("credential", jwt)).body());
            assertTrue(r.get("valid").asBoolean(), () -> "expected valid, got: " + r);
        }
    }

    /** The self-signed CID endpoint mounts and serves a controlled identifier document. */
    @Test
    void ssiCidEndpointServes() throws Exception {
        String sub = claim(idToken(), "sub");
        String uid = sub.substring(sub.lastIndexOf('/') + 1);
        String jsonld = get(base + "/realms/" + REALM + "/lws-ssi-cid/cid/" + uid, "application/ld+json");
        assertTrue(jsonld.contains("\"@context\""), jsonld);
        assertTrue(jsonld.contains("/lws-ssi-cid/cid/" + uid), jsonld);
    }

    /** The SAML endpoint mounts (so keycloak-saml-core resolved at runtime) and demands a cert. */
    @Test
    void samlEndpointMounted() throws Exception {
        HttpResponse<String> r = postForm(base + "/realms/" + REALM + "/lws-saml/verify",
                Map.of("credential", "<samlp:Response/>"));
        assertEquals(400, r.statusCode());
        assertTrue(r.body().contains("certificate"), r.body());
    }

    // ----------------------------------------------------------------------------------- helpers

    private String idToken() throws Exception {
        String body = postForm(base + "/realms/" + REALM + "/protocol/openid-connect/token",
                Map.of("grant_type", "password", "client_id", "lws-app",
                        "username", "alice", "password", "alice", "scope", "openid")).body();
        return JSON.readTree(body).get("id_token").asText();
    }

    private static String claim(String jwt, String name) throws Exception {
        String json = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
        return JSON.readTree(json).get(name).asText();
    }

    private static String mintDidKeyP256() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        return signJwt(DidKey.encodeP256((ECPublicKey) kp.getPublic()), "ES256",
                kp.getPrivate(), "SHA256withECDSAinP1363Format");
    }

    private static String mintDidKeyEd25519() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        return signJwt(DidKey.encodeEd25519(kp.getPublic()), "EdDSA", kp.getPrivate(), "Ed25519");
    }

    private static String signJwt(String did, String alg, PrivateKey key, String jdkAlg) throws Exception {
        long now = System.currentTimeMillis() / 1000;
        String signingInput = b64("{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"}") + "."
                + b64("{\"sub\":\"" + did + "\",\"iss\":\"" + did + "\",\"client_id\":\"" + did
                        + "\",\"aud\":[\"https://as.example\"],\"iat\":" + now + ",\"exp\":" + (now + 300) + "}");
        Signature s = Signature.getInstance(jdkAlg);
        s.initSign(key);
        s.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return signingInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(s.sign());
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String get(String url, String accept) throws Exception {
        return HTTP.send(HttpRequest.newBuilder(URI.create(url)).header("Accept", accept).GET().build(),
                HttpResponse.BodyHandlers.ofString()).body();
    }

    private static HttpResponse<String> postForm(String url, Map<String, String> form) throws Exception {
        String body = form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        return HTTP.send(HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(),
                HttpResponse.BodyHandlers.ofString());
    }
}
