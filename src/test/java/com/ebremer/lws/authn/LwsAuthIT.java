/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Integration test: deploys the built provider JAR into a real Keycloak — the version in the POM — via Testcontainers and
 * runs the same end-to-end smoke flow that was validated by hand — the mapper fires, all three suite
 * endpoints mount, shaded Jena serves/parses RDF, and the OpenID and did:key credentials verify.
 *
 * Requires Docker. Runs in `mvn verify` (failsafe, after the JAR is packaged) and is skipped
 * automatically when Docker is unavailable.
 */
package com.ebremer.lws.authn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.ebremer.lws.authn.did.DidKey;

/**
 * <h2>This suite needs host port 8080, and cannot run in parallel</h2>
 *
 * <p>The OpenID verifier dereferences its own issuer: to validate a credential Keycloak issued, the
 * server fetches a URL that names itself. That URL — the realm issuer — is one string, and it has to
 * resolve to Keycloak from <em>both</em> sides: from this JVM, which reaches the container through a
 * published host port, and from inside the container, where Keycloak is listening on 8080. The only
 * spelling that satisfies both is {@code http://localhost:8080}, with host port 8080 bound straight
 * through to container port 8080.</p>
 *
 * <p><strong>So: if anything else on this machine holds port 8080, this suite fails</strong>, and two
 * copies of it cannot run at once. {@link #requirePort8080()} checks for that before starting the
 * container and says so, rather than letting it surface as a two-minute startup timeout.</p>
 *
 * <p>A random port would need Keycloak to listen on that same port inside the container, and
 * {@code ExtendableKeycloakContainer} hardcodes 8080 in three places — the exposed port, the HTTP wait
 * strategy and the log-wait regex — so moving it means replacing all three and owning the startup
 * detection ourselves. That is a worse trade than one documented port: the failure this causes is
 * loud, immediate and has an obvious fix, and CI runners have 8080 free.</p>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class LwsAuthIT {

    /** The host port the container is bound to; see the class javadoc for why it cannot be random. */
    private static final int FIXED_PORT = 8080;

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final String REALM = "lws-demo";
    /** The Keycloak image: Failsafe passes the POM's {@code keycloak.version}; the default is for IDE runs. */
    private static final String IMAGE = System.getProperty("lws.authn.keycloakImage", "quay.io/keycloak/keycloak:26.8.0");
    /**
     * The shaded provider JAR under test. Failsafe passes its exact path (see the POM); run from an IDE,
     * the newest shaded JAR in {@code target/} is used, so no version number is written down here.
     */
    private static final String PROVIDER_JAR = providerJar();

    private static String providerJar() {
        String configured = System.getProperty("lws.authn.providerJar");
        if (configured != null && !configured.isBlank()) {
            return configured;
        }
        try (var jars = java.nio.file.Files.newDirectoryStream(java.nio.file.Path.of("target"), "lws-authn-*.jar")) {
            java.nio.file.Path newest = null;
            for (java.nio.file.Path jar : jars) {
                if (newest == null || java.nio.file.Files.getLastModifiedTime(jar)
                        .compareTo(java.nio.file.Files.getLastModifiedTime(newest)) > 0) {
                    newest = jar;
                }
            }
            if (newest == null) {
                throw new IllegalStateException("no target/lws-authn-*.jar; run `mvn package` first");
            }
            return newest.toString();
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    private KeycloakContainer keycloak;
    private String base; // http://localhost:8080

    /**
     * A host-side server reachable from inside the Keycloak container, serving whatever a test asks it
     * to at whatever path.
     *
     * <p>It started out publishing one controlled identifier document as JSON-LD, because nothing else
     * exercises the JSON-LD path in a real deployment: this provider's own CID endpoints serve Turtle
     * to the verifiers, which ask for it first. It now also plays a third-party OpenID Provider, and
     * plays it badly on request — see "the failure branches" below.</p>
     */
    private HttpServer fixtureServer;
    private int fixturePort;
    private final Map<String, Route> routes = new ConcurrentHashMap<>();
    private KeyPair agentKeyPair;
    private String agentWebId;

    /** One canned response. */
    private record Route(int status, String contentType, String body) {
    }

    @BeforeAll
    void startKeycloak() throws Exception {
        Assumptions.assumeTrue(DockerClientFactory.instance().isDockerAvailable(),
                "Docker is required for the Testcontainers integration test");
        requirePort8080();
        startFixtureServer();
        Testcontainers.exposeHostPorts(fixturePort);
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
        // Bound straight through, not mapped: the issuer URL has to mean Keycloak on both sides of the
        // container boundary. See the class javadoc.
        keycloak.setPortBindings(List.of(FIXED_PORT + ":" + FIXED_PORT));
        keycloak.start();
        base = keycloak.getAuthServerUrl();
    }

    /**
     * Fails immediately, and says why, when something else already holds the port this suite must have.
     *
     * <p>Without it the symptom is Testcontainers waiting two minutes on a health check that will never
     * pass, against a container whose port binding silently went to whatever was already listening.</p>
     */
    private static void requirePort8080() {
        try (java.net.ServerSocket probe = new java.net.ServerSocket()) {
            probe.setReuseAddress(false);
            probe.bind(new InetSocketAddress("localhost", FIXED_PORT), 1);
        } catch (Exception inUse) {
            throw new IllegalStateException("LwsAuthIT needs host port " + FIXED_PORT
                    + ", and something else is listening on it. The OpenID verifier dereferences its own"
                    + " issuer, so that URL must resolve to Keycloak both from this JVM and from inside"
                    + " the container, which only works when " + FIXED_PORT + " is bound straight"
                    + " through. Stop whatever holds it (another copy of this suite, or a local"
                    + " Keycloak) and re-run. See the LwsAuthIT class javadoc.", inUse);
        }
    }

    @AfterAll
    void stopKeycloak() {
        if (keycloak != null) {
            keycloak.stop();
        }
        if (fixtureServer != null) {
            fixtureServer.stop(0);
        }
    }

    /**
     * Starts the fixture server and publishes a JSON-LD controlled identifier document for a freshly
     * minted EC key, at a URL the container can reach.
     */
    private void startFixtureServer() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        agentKeyPair = generator.generateKeyPair();

        fixtureServer = HttpServer.create(new InetSocketAddress("0.0.0.0", 0), 0);
        fixturePort = fixtureServer.getAddress().getPort();
        agentWebId = "http://host.testcontainers.internal:" + fixturePort + "/cid";

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

        routes.put("/cid", new Route(200, "application/ld+json", document));

        // One catch-all rather than a context per path: tests register routes as they need them, and a
        // path nobody registered answers 404, which is itself a case worth being able to produce.
        fixtureServer.createContext("/", exchange -> {
            Route route = routes.get(exchange.getRequestURI().getPath());
            byte[] bytes = (route == null ? "{\"error\":\"no such fixture\"}" : route.body())
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type",
                    route == null ? "application/json" : route.contentType());
            exchange.sendResponseHeaders(route == null ? 404 : route.status(), bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        fixtureServer.start();
    }

    /** Registers a fixture response and returns the URL the container can fetch it from. */
    private String serve(String path, String contentType, String body) {
        routes.put(path, new Route(200, contentType, body));
        return "http://host.testcontainers.internal:" + fixturePort + path;
    }

    /** The URL a fixture path has, whether or not anything is registered there. */
    private String fixtureUrl(String path) {
        return "http://host.testcontainers.internal:" + fixturePort + path;
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

    /**
     * R-05. A realm access token is not an LWS credential. Keycloak writes {@code "typ": "JWT"} in the
     * header of access tokens and ID Tokens alike, and only the payload's {@code typ} ({@code Bearer}
     * here) tells them apart; with the WebID mapper on access tokens, one used to verify as the user's
     * ID Token. Rejected by the type check, whatever the mapper is configured to put in it.
     */
    @Test
    void anAccessTokenIsNotAnLwsCredential() throws Exception {
        JsonNode r = JSON.readTree(postForm(base + "/realms/" + REALM + "/lws/verify",
                Map.of("credential", accessToken()), accessToken()).body());
        assertRejected(r, "tokenIsIdToken");
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

    /**
     * R-36. The public document is readable from any origin, with its {@code ETag}, and a preflight is
     * answered; a verify endpoint, which takes a credential, says nothing about CORS.
     */
    @Test
    void theDocumentIsReadableFromABrowserAndVerifyIsNot() throws Exception {
        String sub = claim(idToken(), "sub");
        HttpResponse<String> document = HTTP.send(HttpRequest.newBuilder(URI.create(sub))
                .header("Accept", "text/turtle").header("Origin", "https://app.example").GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, document.statusCode());
        assertEquals("*", document.headers().firstValue("Access-Control-Allow-Origin").orElse(null));
        assertTrue(document.headers().firstValue("Access-Control-Expose-Headers").orElse("").contains("ETag"));

        HttpResponse<String> preflight = HTTP.send(HttpRequest.newBuilder(URI.create(sub))
                .header("Origin", "https://app.example").header("Access-Control-Request-Method", "GET")
                .header("Access-Control-Request-Headers", "if-none-match")
                .method("OPTIONS", HttpRequest.BodyPublishers.noBody()).build(),
                HttpResponse.BodyHandlers.ofString());
        assertTrue(preflight.statusCode() == 200 || preflight.statusCode() == 204, preflight.toString());
        assertEquals("*", preflight.headers().firstValue("Access-Control-Allow-Origin").orElse(null));

        HttpResponse<String> verify = HTTP.send(HttpRequest.newBuilder(
                        URI.create(base + "/realms/" + REALM + "/lws/verify"))
                .header("Origin", "https://app.example")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("credential=x")).build(),
                HttpResponse.BodyHandlers.ofString());
        assertTrue(verify.headers().firstValue("Access-Control-Allow-Origin").isEmpty(), verify.headers().map().toString());
        // No credential at all: the challenge carries no error code (RFC 6750 §3.1).
        assertEquals(401, verify.statusCode());
        assertFalse(verify.headers().firstValue("WWW-Authenticate").orElse("").contains("error="),
                verify.headers().map().toString());
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

    /**
     * The SAML endpoint mounts. Without a certificate it no longer refuses the request (R-25): trust
     * comes from the realm's SAML identity providers, and a credential they do not vouch for is invalid.
     */
    @Test
    void samlEndpointMounted() throws Exception {
        HttpResponse<String> r = postForm(base + "/realms/" + REALM + "/lws-saml/verify",
                Map.of("credential", "<samlp:Response/>"), accessToken());
        assertEquals(200, r.statusCode(), r.body());
        assertFalse(JSON.readTree(r.body()).get("valid").asBoolean(), r.body());
    }

    /**
     * R-25 and R-22, inside the server. A SAML identity provider configured in the realm is the
     * out-of-band trust the suite means: a Response its key signed, naming its entity ID as the issuer,
     * verifies with no certificate in the request — through Keycloak's identity-provider storage and the
     * server's own XML-DSig provider and JVM policy, which no unit test reaches. One naming an issuer no
     * identity provider has is not trusted, whoever signed it.
     */
    @Test
    void aSamlCredentialIsTrustedThroughTheRealmsIdentityProvider() throws Exception {
        String admin = adminToken();
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair idp = g.generateKeyPair();
        String alias = "lws-it-saml-" + System.nanoTime();
        String entityId = "https://" + alias + ".example/idp";
        String instances = base + "/admin/realms/" + REALM + "/identity-provider/instances";
        HttpResponse<String> created = sendJson("POST", instances, "{\"alias\":\"" + alias + "\",\"providerId\":\"saml\","
                + "\"enabled\":true,\"config\":{\"idpEntityId\":\"" + entityId + "\","
                + "\"singleSignOnServiceUrl\":\"https://" + alias + ".example/sso\","
                + "\"signingCertificate\":\"" + Base64.getEncoder().encodeToString(selfSigned(idp).getEncoded())
                + "\"}}", admin);
        assertEquals(201, created.statusCode(), created.body());
        try {
            String verify = base + "/realms/" + REALM + "/lws-saml/verify";
            HttpResponse<String> r = postForm(verify, Map.of("credential",
                    signedSamlResponse(entityId, "https://id.example/alice", idp.getPrivate()),
                    "audience", SAML_AUDIENCE, "recipient", SAML_AUDIENCE), accessToken());
            assertEquals(200, r.statusCode(), r.body());
            JsonNode result = JSON.readTree(r.body());
            assertTrue(result.get("valid").asBoolean(), r.body());
            assertEquals("identity-provider", result.get("trustSource").asText(), r.body());
            assertEquals(alias, result.get("identityProvider").asText(), r.body());
            assertEquals("https://id.example/alice", result.get("subject").asText(), r.body());

            JsonNode unknown = JSON.readTree(postForm(verify, Map.of("credential",
                    signedSamlResponse("https://no-such-idp.example", "https://id.example/alice", idp.getPrivate()),
                    "audience", SAML_AUDIENCE), accessToken()).body());
            assertFalse(unknown.get("valid").asBoolean(), unknown.toString());
            assertFalse(unknown.get("checks").get("trustedCertificateFound").asBoolean(), unknown.toString());
        } finally {
            sendJson("DELETE", instances + "/" + alias, "", admin);
        }
    }

    /**
     * P0-3: the verify endpoints are authenticated by default. An anonymous POST must be refused
     * before any outbound fetch happens, and — RFC 9110 &sect;15.5.2 — the 401 must carry a challenge,
     * which is also what distinguishes "you may not call this" from "the credential you sent is bad".
     */
    @Test
    void anonymousVerifyIsRefused() throws Exception {
        for (String suite : List.of("lws", "lws-ssi-cid", "lws-saml")) {
            HttpResponse<String> r = postForm(base + "/realms/" + REALM + "/" + suite + "/verify",
                    Map.of("credential", "irrelevant"), null);
            assertEquals(401, r.statusCode(), suite + " must refuse an unauthenticated caller");
            assertNotNull(r.headers().firstValue("WWW-Authenticate").orElse(null),
                    suite + " must send a WWW-Authenticate challenge with its 401");
        }
    }

    /**
     * R-11. Being a user of the realm does not make one a verifier: without the verifier role the caller
     * is refused, and a role taken away stops working at once rather than when the token expires.
     */
    @Test
    void onlyAHolderOfTheVerifierRoleMayVerify() throws Exception {
        String admin = adminToken();
        String username = "caller-" + System.nanoTime();
        String password = "pw-" + username;
        HttpResponse<String> created = sendJson("POST", base + "/admin/realms/" + REALM + "/users",
                "{\"username\":\"" + username + "\",\"enabled\":true,\"emailVerified\":true,"
                        + "\"email\":\"" + username + "@example.org\",\"firstName\":\"A\",\"lastName\":\"Caller\","
                        + "\"credentials\":[{\"type\":\"password\",\"value\":\"" + password + "\",\"temporary\":false}]}",
                admin);
        assertEquals(201, created.statusCode(), created.body());
        String mappings = created.headers().firstValue("Location").orElseThrow() + "/role-mappings/realm";
        String role = "[" + HTTP.send(HttpRequest.newBuilder(URI.create(base + "/admin/realms/" + REALM + "/roles/lws-verifier"))
                .header("Authorization", "Bearer " + admin).GET().build(), HttpResponse.BodyHandlers.ofString()).body() + "]";
        String verify = base + "/realms/" + REALM + "/lws/verify";
        Map<String, String> form = Map.of("credential", idToken());

        HttpResponse<String> refused = postForm(verify, form, userAccessToken(username, password));
        assertEquals(403, refused.statusCode(), "a realm user without the role must be refused");
        assertTrue(refused.body().contains("insufficient_scope"), refused.body());

        assertEquals(204, sendJson("POST", mappings, role, admin).statusCode());
        String granted = userAccessToken(username, password);
        assertEquals(200, postForm(verify, form, granted).statusCode(), "with the role, the caller is answered");

        assertEquals(204, sendJson("DELETE", mappings, role, admin).statusCode());
        assertEquals(403, postForm(verify, form, granted).statusCode(),
                "the same token, its role since taken away, must be refused");
    }

    /**
     * P3-1. An invalid credential is an answer, not a refusal: RFC 9110 §15.5.2 requires a 401 to carry
     * a {@code WWW-Authenticate} challenge, and these used to send a bare 401 for a credential that
     * simply did not verify. The status was wrong as well as incomplete — the request <em>was</em>
     * authorized, and the endpoint answered it. So: 200 with {@code "valid": false}, and 401 reserved
     * for the caller, where {@link #anonymousVerifyIsRefused} shows it still carries a challenge.
     */
    @Test
    void anInvalidCredentialIsTwoHundredWithValidFalse() throws Exception {
        Map<String, String> nonsense = Map.of("credential", "not.a.jwt");
        for (String suite : List.of("lws", "lws-ssi-cid")) {
            HttpResponse<String> r = postForm(base + "/realms/" + REALM + "/" + suite + "/verify",
                    nonsense, accessToken());
            assertEquals(200, r.statusCode(), suite + " answered a rejected credential with a status: " + r.body());
            assertTrue(r.headers().firstValue("WWW-Authenticate").isEmpty(),
                    suite + " must not challenge a caller it accepted");
            assertFalse(JSON.readTree(r.body()).get("valid").asBoolean(), r.body());
        }

        // SAML too, here with a certificate in the request; without one, the realm's identity providers answer.
        HttpResponse<String> saml = postForm(base + "/realms/" + REALM + "/lws-saml/verify",
                Map.of("credential", "<samlp:Response/>", "certificate", selfSignedPem()), accessToken());
        assertEquals(200, saml.statusCode(), saml.body());
        assertFalse(JSON.readTree(saml.body()).get("valid").asBoolean(), saml.body());
    }

    /**
     * P3-2/P3-7. Every non-result answer is the same media type with the same shape, whatever produced
     * it: nothing but the status distinguishes a 404 for an unknown identifier from a 406 or a 400, so
     * there is no incidental oracle in the wording or structure of a refusal.
     */
    @Test
    void everyRefusalIsJsonOfTheSameShape() throws Exception {
        String sub = claim(idToken(), "sub");
        String unknown = sub.substring(0, sub.lastIndexOf('/') + 1) + "00000000-0000-0000-0000-000000000000";

        HttpResponse<String> missing = get(unknown, "text/turtle");
        assertEquals(404, missing.statusCode());
        HttpResponse<String> unacceptable = get(sub, "text/html");
        assertEquals(406, unacceptable.statusCode());
        HttpResponse<String> noCredential = postForm(base + "/realms/" + REALM + "/lws/verify",
                Map.of("audience", "https://as.example"), accessToken());
        assertEquals(400, noCredential.statusCode());

        for (HttpResponse<String> r : List.of(missing, unacceptable, noCredential)) {
            assertTrue(r.headers().firstValue("Content-Type").orElse("").startsWith("application/json"),
                    "an untyped response becomes a 500 in Keycloak: " + r.headers().map());
            JsonNode json = JSON.readTree(r.body());
            assertTrue(json.hasNonNull("error"), r.body());
            assertTrue(json.hasNonNull("error_description"), r.body());
        }
    }

    /**
     * R-16. "The {@code aud} claim MUST include the target authorization server": with no target named
     * by the request or the deployment there is no verdict to give, so the request is refused.
     */
    @Test
    void aSelfSignedCidRequestWithoutAnAudienceIsRefused() throws Exception {
        HttpResponse<String> r = postForm(base + "/realms/" + REALM + "/lws-ssi-cid/verify",
                Map.of("credential", mintDidKeyP256()), accessToken());
        assertEquals(400, r.statusCode(), r.body());
        assertTrue(r.body().contains("audience"), r.body());
    }

    /** A token from another realm is not a caller credential for this one. */
    @Test
    void aBadCallerTokenIsRefused() throws Exception {
        HttpResponse<String> r = postForm(base + "/realms/" + REALM + "/lws-ssi-cid/verify",
                Map.of("credential", mintDidKeyP256()), "not-a-token");
        assertEquals(401, r.statusCode(), "a bogus bearer token must not be accepted");
    }

    // --------------------------------------------------- the failure branches (P5-1 / P5-2 / P5-4)
    //
    // Everything above this line asserts that a good credential is accepted. These assert that a bad
    // one is refused, which is the direction where a bug is silent: a verifier that wrongly rejects
    // gets reported by its users, and a verifier that wrongly *accepts* does not.
    //
    // They live here rather than in a unit test because the branches they reach are all downstream of
    // an outbound fetch, and driving that off-container means mocking KeycloakSession — at which point
    // the crypto and the classpath are imitations, and both bugs this suite has actually caught were
    // invisible to imitations by construction. The container is already running; each case here costs
    // a fraction of a second.

    /**
     * The control for every OpenID case below: the same fixture, unbroken, must verify. Without this,
     * a fixture that was simply malformed would make all six negative assertions pass vacuously.
     *
     * <p>It is also worth having in its own right — the OpenID happy path elsewhere runs against
     * Keycloak itself, and this one runs against a third-party provider serving a Turtle CID.</p>
     */
    @Test
    void aThirdPartyOpenIdProviderVerifies() throws Exception {
        OpenIdFixture op = new OpenIdFixture("control");
        JsonNode r = op.verify();
        assertTrue(r.get("valid").asBoolean(), () -> "the unbroken fixture must verify, got: " + r);
    }

    /** OpenID Connect Discovery returning a configuration that names a different issuer. */
    @Test
    void openIdDiscoveryIssuerMismatchIsRejected() throws Exception {
        OpenIdFixture op = new OpenIdFixture("issuer-mismatch");
        op.serveDiscovery("{\"issuer\":\"https://somewhere-else.example\",\"jwks_uri\":\""
                + op.jwksUrl + "\"}");
        assertRejected(op.verify(), "issuerDiscoveryMatches");
    }

    /** A configuration document with no {@code jwks_uri}: there is no key to check the signature with. */
    @Test
    void openIdDiscoveryWithoutJwksUriIsRejected() throws Exception {
        OpenIdFixture op = new OpenIdFixture("no-jwks-uri");
        op.serveDiscovery("{\"issuer\":\"" + op.issuer + "\"}");
        assertRejected(op.verify(), "jwksResolved");
    }

    /** A JWKS that publishes keys, none of them the {@code kid} the token names. */
    @Test
    void openIdJwksWithNoMatchingKidIsRejected() throws Exception {
        OpenIdFixture op = new OpenIdFixture("kid-mismatch");
        op.serveJwks("{\"keys\":[" + op.jwk("a-different-key") + "]}");
        assertRejected(op.verify(), "jwksResolved");
    }

    /**
     * Algorithm confusion (the reason {@code algMatchesKey} exists): a token claiming {@code HS256},
     * hoping the provider's RSA <em>public</em> key — which is public — gets used as an HMAC secret.
     * The key selection refuses to hand back a key whose type cannot produce the declared algorithm,
     * so the token never reaches a verifier at all.
     */
    @Test
    void openIdHs256AgainstAnRsaKeyIsRejected() throws Exception {
        OpenIdFixture op = new OpenIdFixture("hs256-confusion");
        String signingInput = b64("{\"alg\":\"HS256\",\"kid\":\"op-key\",\"typ\":\"JWT\"}")
                + "." + b64(op.claims());
        Mac mac = Mac.getInstance("HmacSHA256");
        // The forger's guess at the secret: the provider's public modulus, which anyone can fetch.
        mac.init(new SecretKeySpec(magnitude(((RSAPublicKey) op.keyPair.getPublic()).getModulus()),
                "HmacSHA256"));
        String forged = signingInput + "." + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8)));
        assertRejected(op.verify(forged, Map.of()), "jwksResolved");
    }

    /**
     * A subject whose controlled identifier document dereferences perfectly well but never says this
     * issuer speaks for it — the step that stops any OpenID Provider vouching for any subject.
     */
    @Test
    void openIdSubjectNotDeclaringTheProviderIsRejected() throws Exception {
        OpenIdFixture op = new OpenIdFixture("no-service");
        op.serveCid("<" + op.subject + "> <https://www.w3.org/ns/did#service> <" + op.subject + "#other> .\n"
                + "<" + op.subject + "#other> a <https://www.w3.org/ns/lws#SomethingElse> ;\n"
                + "  <https://www.w3.org/ns/did#serviceEndpoint> <" + op.issuer + "> .");
        assertRejected(op.verify(), "openIdProviderServiceLocated");
    }

    /**
     * OpenID Connect Core §3.1.3.7 steps 3-5, which the suite incorporates by reference: a token minted
     * for one relying party must not verify for another. Run against Keycloak's own ID Token, because
     * that is the credential a real caller holds.
     */
    @Test
    void anIdTokenMintedForAnotherRelyingPartyIsRejected() throws Exception {
        JsonNode wrongClient = verifyOpenId(Map.of("credential", idToken(), "client_id", "some-other-app"));
        assertRejected(wrongClient, "audienceContainsClient");

        JsonNode wrongAudience = verifyOpenId(Map.of("credential", idToken(),
                "audience", "https://not-this-server.example"));
        assertRejected(wrongAudience, "audienceMatched");

        // And the control: the same token, named correctly, still verifies.
        JsonNode right = verifyOpenId(Map.of("credential", idToken(), "client_id", "lws-app"));
        assertTrue(right.get("valid").asBoolean(), () -> "expected valid, got: " + right);
    }

    /**
     * Self-signed CID: a verification method the subject does not control. Anyone can serve a document
     * listing anyone's key; what makes it evidence is the subject claiming it.
     */
    @Test
    void ssiCidMethodWithAForeignControllerIsRejected() throws Exception {
        String subject = serveSsiCidDocument("/ssi/foreign-controller",
                "https://someone-else.example", "");
        assertRejected(verifySsiCid(mintSsiCidJwt(subject, "ES256")), "verificationMethodFound");
    }

    /** Self-signed CID: a key its own holder published for encryption, not for signing. */
    @Test
    void ssiCidMethodPublishedForEncryptionIsRejected() throws Exception {
        String subject = serveSsiCidDocument("/ssi/use-enc", null, ",\"use\":\"enc\"");
        assertRejected(verifySsiCid(mintSsiCidJwt(subject, "ES256")),
                "verificationMethodUsableForSigning");
    }

    /** Self-signed CID: a token whose {@code alg} is not the one the published JWK is pinned to. */
    @Test
    void ssiCidAlgorithmInconsistentWithThePublishedKeyIsRejected() throws Exception {
        String subject = serveSsiCidDocument("/ssi/alg-mismatch", null, ",\"alg\":\"ES384\"");
        assertRejected(verifySsiCid(mintSsiCidJwt(subject, "ES256")),
                "verificationMethodUsableForSigning");
    }

    /** did:key: the identifier carries the key, so a token signed by any other key cannot verify. */
    @Test
    void didKeyTokenSignedByAnotherKeyIsRejected() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        String did = DidKey.encodeP256((ECPublicKey) g.generateKeyPair().getPublic());
        KeyPair impostor = g.generateKeyPair();

        String jwt = signJwt(did, "ES256", did + "#" + DidKey.multibaseValue(did), impostor.getPrivate(),
                "SHA256withECDSAinP1363Format");
        assertRejected(verifySsiCid(jwt), "signatureValid");
    }

    // ------------------------------------------------------- fixtures for the failure branches

    /**
     * A third-party OpenID Provider, plus the controlled identifier document that points at it, both
     * served from the host-side fixture server. Everything starts out correct; a test then replaces
     * exactly one of the three documents and asserts the verifier notices that one thing.
     */
    private final class OpenIdFixture {

        private static final String CLIENT_ID = "fixture-client";

        private final String subject;
        private final String issuer;
        private final String jwksUrl;
        private final KeyPair keyPair;

        OpenIdFixture(String name) throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();

            subject = fixtureUrl("/op/" + name + "/subject");
            issuer = fixtureUrl("/op/" + name);
            jwksUrl = fixtureUrl("/op/" + name + "/jwks");

            // Turtle, which is what the verifiers ask for first; the JSON-LD path is covered elsewhere.
            serveCid("<" + subject + "> <https://www.w3.org/ns/did#service> <" + subject + "#op> .\n"
                    + "<" + subject + "#op> a <https://www.w3.org/ns/lws#OpenIdProvider> ;\n"
                    + "  <https://www.w3.org/ns/did#serviceEndpoint> <" + issuer + "> .");
            serveDiscovery("{\"issuer\":\"" + issuer + "\",\"jwks_uri\":\"" + jwksUrl + "\"}");
            serveJwks("{\"keys\":[" + jwk("op-key") + "]}");
        }

        void serveCid(String turtle) {
            serve(URI.create(subject).getPath(), "text/turtle", turtle);
        }

        void serveDiscovery(String json) {
            serve(URI.create(issuer).getPath() + "/.well-known/openid-configuration",
                    "application/json", json);
        }

        void serveJwks(String json) {
            serve(URI.create(jwksUrl).getPath(), "application/json", json);
        }

        /** This provider's RSA public key as a JWK, under whatever {@code kid} the caller wants. */
        String jwk(String kid) {
            RSAPublicKey key = (RSAPublicKey) keyPair.getPublic();
            return "{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"" + kid + "\","
                    + "\"n\":\"" + b64u(magnitude(key.getModulus())) + "\","
                    + "\"e\":\"" + b64u(magnitude(key.getPublicExponent())) + "\"}";
        }

        /** The claim set of a well-formed ID Token from this provider. */
        String claims() {
            long now = System.currentTimeMillis() / 1000;
            return "{\"sub\":\"" + subject + "\",\"iss\":\"" + issuer + "\",\"azp\":\"" + CLIENT_ID + "\","
                    + "\"aud\":[\"" + CLIENT_ID + "\"],\"iat\":" + now + ",\"exp\":" + (now + 300) + "}";
        }

        /** A correctly signed ID Token from this provider. */
        String idToken() throws Exception {
            String signingInput = b64("{\"alg\":\"RS256\",\"kid\":\"op-key\",\"typ\":\"JWT\"}")
                    + "." + b64(claims());
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return signingInput + "."
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
        }

        JsonNode verify() throws Exception {
            return verify(idToken(), Map.of("client_id", CLIENT_ID));
        }

        JsonNode verify(String credential, Map<String, String> extra) throws Exception {
            Map<String, String> form = new java.util.LinkedHashMap<>(extra);
            form.put("credential", credential);
            return verifyOpenId(form);
        }
    }

    /**
     * Serves a self-signed-CID document for {@link #agentKeyPair} with one thing altered, and returns
     * the subject it describes.
     *
     * @param controller     the method's {@code controller}, or {@code null} for the subject itself
     * @param extraJwkMembers additional JWK members, each with its leading comma
     */
    private String serveSsiCidDocument(String path, String controller, String extraJwkMembers) {
        String subject = fixtureUrl(path);
        ECPublicKey key = (ECPublicKey) agentKeyPair.getPublic();
        String document = "{\"@context\":[\"https://www.w3.org/ns/cid/v1\"],"
                + "\"id\":\"" + subject + "\","
                + "\"authentication\":[{\"id\":\"" + subject + "#k1\",\"type\":\"JsonWebKey\","
                + "\"controller\":\"" + (controller == null ? subject : controller) + "\","
                + "\"publicKeyJwk\":{\"kid\":\"k1\",\"kty\":\"EC\",\"crv\":\"P-256\","
                + "\"x\":\"" + b64(key.getW().getAffineX()) + "\","
                + "\"y\":\"" + b64(key.getW().getAffineY()) + "\"" + extraJwkMembers + "}}]}";
        serve(path, "application/ld+json", document);
        return subject;
    }

    /** A correctly signed self-issued JWT for {@code subject}, declaring {@code alg} in its header. */
    private String mintSsiCidJwt(String subject, String alg) throws Exception {
        long now = System.currentTimeMillis() / 1000;
        String signingInput = b64("{\"alg\":\"" + alg + "\",\"kid\":\"k1\",\"typ\":\"JWT\"}") + "."
                + b64("{\"sub\":\"" + subject + "\",\"iss\":\"" + subject + "\","
                        + "\"client_id\":\"" + subject + "\",\"aud\":[\"https://as.example\"],"
                        + "\"iat\":" + now + ",\"exp\":" + (now + 300) + "}");
        Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(agentKeyPair.getPrivate());
        signer.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return signingInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
    }

    // ------------------------------------------------ did:key under the self-signed CID suite

    /**
     * The did:key suite was discontinued (18 September 2026) in favour of the self-signed CID suite,
     * which "is designed to work with subject identifiers that use HTTPS URIs as well as DID URIs". A
     * did:key credential verifies there, with its {@code kid} naming the method the DID document's
     * {@code authentication} relationship lists. Ed25519 goes through Keycloak's own EdDSA signature
     * provider here, which nothing else in this suite exercises.
     */
    @Test
    void didKeyCredentialsVerifyUnderTheSelfSignedCidSuite() throws Exception {
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair p256 = ec.generateKeyPair();
        String p256Did = DidKey.encodeP256((ECPublicKey) p256.getPublic());
        KeyPair ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String edDid = DidKey.encodeEd25519(ed.getPublic());

        for (String jwt : List.of(
                signJwt(p256Did, "ES256", p256Did + "#" + DidKey.multibaseValue(p256Did), p256.getPrivate(),
                        "SHA256withECDSAinP1363Format"),
                signJwt(edDid, "EdDSA", edDid + "#" + DidKey.multibaseValue(edDid), ed.getPrivate(), "Ed25519"))) {
            JsonNode r = verifySsiCid(jwt);
            assertTrue(r.get("valid").asBoolean(), () -> "expected valid, got: " + r);
        }

        // The one rule the discontinued suite did not have: the kid is required.
        assertRejected(verifySsiCid(signJwt(edDid, "EdDSA", ed.getPrivate(), "Ed25519")), "keyIdPresent");
    }

    /**
     * R-34. {@code single_use=true} records the credential in Keycloak's single-use object store, and the
     * second request that asks the same is refused; one that does not ask still gets {@code valid: true}.
     */
    @Test
    void aCredentialHeldToSingleUseVerifiesOnce() throws Exception {
        KeyPair ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String did = DidKey.encodeEd25519(ed.getPublic());
        String jwt = signJwt(did, "EdDSA", did + "#" + DidKey.multibaseValue(did), ed.getPrivate(), "Ed25519",
                java.util.UUID.randomUUID().toString());
        Map<String, String> once = Map.of("credential", jwt, "audience", "https://as.example", "single_use", "true");
        String url = base + "/realms/" + REALM + "/lws-ssi-cid/verify";

        JsonNode first = JSON.readTree(postForm(url, once, accessToken()).body());
        assertTrue(first.get("valid").asBoolean(), () -> "expected valid, got: " + first);
        assertRejected(JSON.readTree(postForm(url, once, accessToken()).body()), "notReplayed");
        JsonNode unasked = verifySsiCid(jwt);
        assertTrue(unasked.get("valid").asBoolean(), () -> "expected valid, got: " + unasked);
    }

    /**
     * The discontinued did:key suite's endpoint was removed rather than kept deprecated. Its path must
     * be unknown to Keycloak — a provider still registered under that id would answer here.
     */
    @Test
    void theDiscontinuedDidKeyEndpointIsGone() throws Exception {
        HttpResponse<String> r = postForm(base + "/realms/" + REALM + "/lws-ssi-did-key/verify",
                Map.of("credential", mintDidKeyP256()), accessToken());
        assertEquals(404, r.statusCode(), r.body());
    }

    private JsonNode verifyOpenId(Map<String, String> form) throws Exception {
        return JSON.readTree(
                postForm(base + "/realms/" + REALM + "/lws/verify", form, accessToken()).body());
    }

    private JsonNode verifySsiCid(String credential) throws Exception {
        return JSON.readTree(postForm(base + "/realms/" + REALM + "/lws-ssi-cid/verify",
                Map.of("credential", credential, "audience", "https://as.example"), accessToken()).body());
    }

    /**
     * Asserts the credential was refused, and refused for the stated reason.
     *
     * <p>Naming the check matters: "not valid" is satisfied by a fixture that simply failed to load, so
     * an assertion that only looked at {@code valid} would keep passing after the branch it was written
     * for stopped being reachable.</p>
     */
    private static void assertRejected(JsonNode result, String failedCheck) {
        assertFalse(result.get("valid").asBoolean(),
                () -> "expected the credential to be rejected, got: " + result);
        JsonNode checks = result.get("checks");
        assertNotNull(checks.get(failedCheck),
                () -> "no '" + failedCheck + "' check was recorded: " + result);
        assertFalse(checks.get(failedCheck).asBoolean(),
                () -> "expected '" + failedCheck + "' to be the failing check: " + result);
    }

    /** A big integer as its unsigned big-endian bytes, which is what a JWK and an HMAC key both want. */
    private static byte[] magnitude(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            byte[] trimmed = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
            return trimmed;
        }
        return bytes;
    }

    private static String b64u(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
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

    private String userAccessToken(String username, String password) throws Exception {
        return JSON.readTree(postForm(base + "/realms/" + REALM + "/protocol/openid-connect/token",
                Map.of("grant_type", "password", "client_id", "lws-app",
                        "username", username, "password", password, "scope", "openid"), null).body())
                .get("access_token").asText();
    }

    /** A token for the master realm's administrator, for the admin REST API. */
    private String adminToken() throws Exception {
        return JSON.readTree(postForm(base + "/realms/master/protocol/openid-connect/token",
                Map.of("grant_type", "password", "client_id", "admin-cli", "username", keycloak.getAdminUsername(),
                        "password", keycloak.getAdminPassword()), null).body()).get("access_token").asText();
    }

    private static HttpResponse<String> sendJson(String method, String url, String json, String bearer)
            throws Exception {
        return HTTP.send(HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + bearer)
                .method(method, HttpRequest.BodyPublishers.ofString(json)).build(), HttpResponse.BodyHandlers.ofString());
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

    /**
     * A throwaway self-signed certificate, PEM-encoded: enough for the SAML endpoint to get past its
     * parameter checks and actually reject the credential, which is what the caller wants to observe.
     */
    private static String selfSignedPem() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        X509Certificate certificate = selfSigned(g.generateKeyPair());
        // Encoded here rather than with Keycloak's PemUtils: that needs CryptoIntegration to have been
        // initialised, which happens inside the server, not in this JVM.
        return "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----";
    }

    private static X509Certificate selfSigned(KeyPair kp) throws Exception {
        long now = System.currentTimeMillis();
        X500Name dn = new X500Name("CN=lws-authn-it");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(dn, BigInteger.valueOf(now),
                        new Date(now - 1000L), new Date(now + 86_400_000L), dn, kp.getPublic()).build(signer));
    }

    /** The SAML audience and bearer Recipient — the LWS client identifier — of every IT assertion. */
    private static final String SAML_AUDIENCE = "https://app.example/SAML";

    /**
     * A SAML Response as an IdP sends one: a bearer assertion from {@code issuer} about {@code nameId},
     * signed with an enveloped RSA-SHA256 signature, exclusive canonicalization, and SHA-256 digest.
     */
    private static String signedSamlResponse(String issuer, String nameId, PrivateKey key) throws Exception {
        java.time.Instant now = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        String saml = "urn:oasis:names:tc:SAML:2.0:assertion";
        String xml = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"" + saml
                + "\" ID=\"r1\" Version=\"2.0\" IssueInstant=\"" + now + "\">"
                + "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>"
                + "<saml:Assertion ID=\"a1\" Version=\"2.0\" IssueInstant=\"" + now + "\">"
                + "<saml:Issuer>" + issuer + "</saml:Issuer>"
                + "<saml:Subject><saml:NameID>" + nameId + "</saml:NameID>"
                + "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                + "<saml:SubjectConfirmationData Recipient=\"" + SAML_AUDIENCE + "\" NotOnOrAfter=\""
                + now.plusSeconds(300) + "\"/></saml:SubjectConfirmation></saml:Subject>"
                + "<saml:Conditions NotBefore=\"" + now.minusSeconds(60) + "\" NotOnOrAfter=\"" + now.plusSeconds(300) + "\">"
                + "<saml:AudienceRestriction><saml:Audience>" + SAML_AUDIENCE + "</saml:Audience></saml:AudienceRestriction>"
                + "</saml:Conditions>"
                + "<saml:AuthnStatement AuthnInstant=\"" + now + "\"><saml:AuthnContext><saml:AuthnContextClassRef>"
                + "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef></saml:AuthnContext>"
                + "</saml:AuthnStatement></saml:Assertion></samlp:Response>";
        javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        org.w3c.dom.Document doc = dbf.newDocumentBuilder()
                .parse(new java.io.ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        org.w3c.dom.Element assertion = (org.w3c.dom.Element) doc.getElementsByTagNameNS(saml, "Assertion").item(0);
        assertion.setIdAttribute("ID", true);
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference reference = fac.newReference("#a1", fac.newDigestMethod(DigestMethod.SHA256, null),
                List.of(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                        fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null)),
                null, null);
        SignedInfo signedInfo = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        fac.newXMLSignature(signedInfo, null).sign(new DOMSignContext(key, assertion));
        java.io.StringWriter out = new java.io.StringWriter();
        javax.xml.transform.TransformerFactory.newInstance().newTransformer().transform(
                new javax.xml.transform.dom.DOMSource(doc), new javax.xml.transform.stream.StreamResult(out));
        return out.toString();
    }

    private static String mintDidKeyP256() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        return signJwt(DidKey.encodeP256((ECPublicKey) kp.getPublic()), "ES256",
                kp.getPrivate(), "SHA256withECDSAinP1363Format");
    }

    private static String signJwt(String did, String alg, PrivateKey key, String jdkAlg) throws Exception {
        return signJwt(did, alg, null, key, jdkAlg);
    }

    private static String signJwt(String did, String alg, String kid, PrivateKey key, String jdkAlg)
            throws Exception {
        return signJwt(did, alg, kid, key, jdkAlg, null);
    }

    private static String signJwt(String did, String alg, String kid, PrivateKey key, String jdkAlg, String jti)
            throws Exception {
        long now = System.currentTimeMillis() / 1000;
        String signingInput = b64("{\"alg\":\"" + alg + "\",\"typ\":\"JWT\""
                        + (kid == null ? "" : ",\"kid\":\"" + kid + "\"") + "}") + "."
                + b64("{\"sub\":\"" + did + "\",\"iss\":\"" + did + "\",\"client_id\":\"" + did
                        + "\",\"aud\":[\"https://as.example\"],\"iat\":" + now + ",\"exp\":" + (now + 300)
                        + (jti == null ? "" : ",\"jti\":\"" + jti + "\"") + "}");
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
