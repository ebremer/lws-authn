/*
 * Copyright Erich Bremer.
 *
 * Integration test: deploys the built provider JAR into a real Keycloak 26.7.3 via Testcontainers and
 * runs the same end-to-end smoke flow that was validated by hand — the mapper fires, all four suite
 * endpoints mount, shaded Jena serves/parses RDF, and the OpenID and did:key credentials verify.
 *
 * Requires Docker. Runs in `mvn verify` (failsafe, after the JAR is packaged) and is skipped
 * automatically when Docker is unavailable.
 */
package com.ebremer.lws.authn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.OutputStream;
import java.net.InetSocketAddress;
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
import com.sun.net.httpserver.HttpServer;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.Testcontainers;

import com.ebremer.lws.authn.ssididkey.DidKey;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LwsAuthIT {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final String REALM = "lws-demo";
    private static final String IMAGE = "quay.io/keycloak/keycloak:26.7.3";
    private static final String PROVIDER_JAR = "target/lws-authn-0.1.0.jar";

    private KeycloakContainer keycloak;
    private String base; // http://localhost:8080

    /**
     * A host-side server publishing a controlled identifier document as JSON-LD, reachable from inside
     * the Keycloak container. Nothing else exercises the JSON-LD path in a real deployment: this
     * provider's own CID endpoints serve Turtle to the verifiers, which ask for it first.
     */
    private HttpServer cidServer;
    private int cidPort;
    private KeyPair agentKeyPair;
    private String agentWebId;

    @BeforeAll
    void startKeycloak() throws Exception {
        Assumptions.assumeTrue(DockerClientFactory.instance().isDockerAvailable(),
                "Docker is required for the Testcontainers integration test");
        startCidServer();
        Testcontainers.exposeHostPorts(cidPort);
        keycloak = new KeycloakContainer(IMAGE)
                .withProviderLibsFrom(List.of(new File(PROVIDER_JAR)))
                .withRealmImportFile("lws-demo-realm.json")
                // The OpenID verifier self-dereferences the realm issuer (a loopback URL here), so the
                // SSRF guard must be told that loopback is an intended target in this deployment.
                // host.testcontainers.internal resolves to the host from inside the container, so the
                // SSRF guard must be told it is an intended target here — the same opt-in a single-box
                // deployment needs to dereference its own documents.
                .withEnv("LWS_AUTHN_ALLOWED_INTERNAL_HOSTS", "localhost,127.0.0.1,host.testcontainers.internal")
                // The verifiers deliberately return terse errors and log the detail under a trace id,
                // so without this a failure here says only "could not be validated".
                .withEnv("KC_LOG_LEVEL", "INFO,com.ebremer.lws.authn:DEBUG")
                .withLogConsumer(f -> { String l = f.getUtf8String(); if (l.contains("com.ebremer")) System.out.print(l); });
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
        if (cidServer != null) {
            cidServer.stop(0);
        }
    }

    /**
     * Publishes a JSON-LD controlled identifier document for a freshly minted EC key, at a URL the
     * container can reach.
     */
    private void startCidServer() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        agentKeyPair = generator.generateKeyPair();

        cidServer = HttpServer.create(new InetSocketAddress("0.0.0.0", 0), 0);
        cidPort = cidServer.getAddress().getPort();
        agentWebId = "http://host.testcontainers.internal:" + cidPort + "/cid";

        ECPublicKey publicKey = (ECPublicKey) agentKeyPair.getPublic();
        String x = b64(publicKey.getW().getAffineX());
        String y = b64(publicKey.getW().getAffineY());
        // Deliberately not the compact spelling this provider emits: an aliased term and an @graph
        // wrapper, both of which the old key-walking reader would have silently found nothing in.
        String document = "{\"@context\":[\"https://www.w3.org/ns/cid/v1\","
                + "{\"auth\":\"https://w3id.org/security#authenticationMethod\"}],"
                + "\"@graph\":[{\"id\":\"" + agentWebId + "\","
                + "\"auth\":[{\"id\":\"" + agentWebId + "#k1\",\"type\":\"JsonWebKey\","
                + "\"controller\":\"" + agentWebId + "\","
                + "\"publicKeyJwk\":{\"kid\":\"k1\",\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"" + x + "\",\"y\":\"" + y + "\"}}]}]}";

        cidServer.createContext("/cid", exchange -> {
            byte[] bytes = document.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/ld+json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        cidServer.start();
    }

    private static String b64(java.math.BigInteger coordinate) {
        byte[] raw = coordinate.toByteArray();
        byte[] fixed = new byte[32];
        if (raw.length >= 32) {
            System.arraycopy(raw, raw.length - 32, fixed, 0, 32);
        } else {
            System.arraycopy(raw, 0, fixed, 32 - raw.length, raw.length);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(fixed);
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
        String turtle = body(sub, "text/turtle");
        assertTrue(turtle.contains("https://www.w3.org/ns/lws#OpenIdProvider"), turtle);
        assertTrue(turtle.contains("https://www.w3.org/ns/did#serviceEndpoint"), turtle);
        String jsonld = body(sub, "application/ld+json");
        assertTrue(jsonld.contains("\"@context\""), jsonld);
        assertTrue(jsonld.contains("OpenIdProvider"), jsonld);
    }

    /** Full OpenID validation: dereference sub, locate service (Jena/SPARQL), discovery, signature. */
    @Test
    void openIdCredentialVerifies() throws Exception {
        JsonNode r = JSON.readTree(postForm(base + "/realms/" + REALM + "/lws/verify",
                Map.of("credential", idToken()), accessToken()).body());
        assertTrue(r.get("valid").asBoolean(), () -> "expected valid, got: " + r);
        r.get("checks").fields().forEachRemaining(e ->
                assertTrue(e.getValue().asBoolean(), "check failed: " + e.getKey()));
    }

    /** did:key suite: self-signed credentials verify for both P-256 and Ed25519. */
    @Test
    void didKeyCredentialsVerify() throws Exception {
        for (String jwt : List.of(mintDidKeyP256(), mintDidKeyEd25519())) {
            JsonNode r = JSON.readTree(postForm(base + "/realms/" + REALM + "/lws-ssi-did-key/verify",
                    Map.of("credential", jwt), accessToken()).body());
            assertTrue(r.get("valid").asBoolean(), () -> "expected valid, got: " + r);
        }
    }

    /**
     * P2-1, and the packaging that carries it. The verifier dereferences a document served as JSON-LD
     * by a third party, written with an aliased term inside an {@code @graph} — a shape the old
     * key-walking reader could not see at all. Passing means Jena's JSON-LD 1.1 reader works inside
     * Keycloak with Titanium *relocated* and jakarta.json taken from the server, which no unit test can
     * establish: they run against the unshaded classpath.
     */
    @Test
    void jsonLdControlledIdentifierDocumentVerifies() throws Exception {
        long now = System.currentTimeMillis() / 1000;
        String signingInput = b64("{\"alg\":\"ES256\",\"kid\":\"k1\",\"typ\":\"JWT\"}") + "."
                + b64("{\"sub\":\"" + agentWebId + "\",\"iss\":\"" + agentWebId + "\","
                        + "\"client_id\":\"" + agentWebId + "\",\"aud\":[\"https://as.example\"],"
                        + "\"iat\":" + now + ",\"exp\":" + (now + 300) + "}");
        Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(agentKeyPair.getPrivate());
        signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
        String jwt = signingInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());

        JsonNode r = JSON.readTree(postForm(base + "/realms/" + REALM + "/lws-ssi-cid/verify",
                Map.of("credential", jwt, "audience", "https://as.example"), accessToken()).body());
        assertTrue(r.get("valid").asBoolean(), () -> "expected valid, got: " + r);
        assertEquals(agentWebId, r.get("subject").asText());
    }

    /** P2-2/3/4: the CID endpoint honours q-values and carries cache headers. */
    @Test
    void cidEndpointNegotiatesAndIsCacheable() throws Exception {
        String sub = claim(idToken(), "sub");

        HttpResponse<String> turtle = get(sub, "application/ld+json;q=0.1, text/turtle;q=1.0");
        assertEquals(200, turtle.statusCode());
        assertTrue(turtle.headers().firstValue("Content-Type").orElse("").startsWith("text/turtle"),
                "the highest q-value must win: " + turtle.headers().map());
        assertEquals("Accept", turtle.headers().firstValue("Vary").orElse(null));
        assertTrue(turtle.headers().firstValue("Cache-Control").orElse("").contains("max-age"));

        String etag = turtle.headers().firstValue("ETag").orElse(null);
        assertNotNull(etag, "a cacheable document needs a validator");
        HttpResponse<String> conditional = HTTP.send(HttpRequest.newBuilder(URI.create(sub))
                .header("Accept", "text/turtle").header("If-None-Match", etag).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(304, conditional.statusCode(), "an unchanged document should answer If-None-Match");

        HttpResponse<String> unacceptable = get(sub, "text/html");
        assertEquals(406, unacceptable.statusCode(),
                "an Accept naming nothing on offer used to be answered with JSON-LD anyway");
    }

    /** The self-signed CID endpoint mounts and serves a controlled identifier document. */
    @Test
    void ssiCidEndpointServes() throws Exception {
        String sub = claim(idToken(), "sub");
        String uid = sub.substring(sub.lastIndexOf('/') + 1);
        String jsonld = body(base + "/realms/" + REALM + "/lws-ssi-cid/cid/" + uid, "application/ld+json");
        assertTrue(jsonld.contains("\"@context\""), jsonld);
        assertTrue(jsonld.contains("/lws-ssi-cid/cid/" + uid), jsonld);
    }

    /** The SAML endpoint mounts (so keycloak-saml-core resolved at runtime) and demands a cert. */
    @Test
    void samlEndpointMounted() throws Exception {
        HttpResponse<String> r = postForm(base + "/realms/" + REALM + "/lws-saml/verify",
                Map.of("credential", "<samlp:Response/>"), accessToken());
        assertEquals(400, r.statusCode());
        assertTrue(r.body().contains("certificate"), r.body());
    }

    /**
     * P0-3: the verify endpoints are authenticated by default. An anonymous POST must be refused
     * before any outbound fetch happens, and — RFC 9110 &sect;15.5.2 — the 401 must carry a challenge,
     * which is also what distinguishes "you may not call this" from "the credential you sent is bad".
     */
    @Test
    void anonymousVerifyIsRefused() throws Exception {
        for (String suite : List.of("lws", "lws-ssi-cid", "lws-ssi-did-key", "lws-saml")) {
            HttpResponse<String> r = postForm(base + "/realms/" + REALM + "/" + suite + "/verify",
                    Map.of("credential", "irrelevant"), null);
            assertEquals(401, r.statusCode(), suite + " must refuse an unauthenticated caller");
            assertNotNull(r.headers().firstValue("WWW-Authenticate").orElse(null),
                    suite + " must send a WWW-Authenticate challenge with its 401");
        }
    }

    /** A token from another realm is not a caller credential for this one. */
    @Test
    void aBadCallerTokenIsRefused() throws Exception {
        HttpResponse<String> r = postForm(base + "/realms/" + REALM + "/lws-ssi-did-key/verify",
                Map.of("credential", mintDidKeyP256()), "not-a-token");
        assertEquals(401, r.statusCode(), "a bogus bearer token must not be accepted");
    }

    // ----------------------------------------------------------------------------------- helpers

    private String idToken() throws Exception {
        return JSON.readTree(tokenResponse()).get("id_token").asText();
    }

    /**
     * The caller's own credential. Since P0-3 the verify endpoints are authenticated by default, so the
     * credential under test travels in the form body and the Authorization header identifies the
     * caller — the standard HTTP reading of that header, and the only one that lets the endpoint be
     * closed to anonymous use.
     */
    private String accessToken() throws Exception {
        return JSON.readTree(tokenResponse()).get("access_token").asText();
    }

    private String tokenResponse() throws Exception {
        return postForm(base + "/realms/" + REALM + "/protocol/openid-connect/token",
                Map.of("grant_type", "password", "client_id", "lws-app",
                        "username", "alice", "password", "alice", "scope", "openid"), null).body();
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

    private static HttpResponse<String> get(String url, String accept) throws Exception {
        return HTTP.send(HttpRequest.newBuilder(URI.create(url)).header("Accept", accept).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private static String body(String url, String accept) throws Exception {
        return get(url, accept).body();
    }

    /** POSTs a form, optionally authenticating the caller with {@code bearer}. */
    private static HttpResponse<String> postForm(String url, Map<String, String> form, String bearer)
            throws Exception {
        String body = form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (bearer != null) {
            request.header("Authorization", "Bearer " + bearer);
        }
        return HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
}
