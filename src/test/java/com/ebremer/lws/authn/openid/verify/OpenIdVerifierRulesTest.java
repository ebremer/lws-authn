/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.openid.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.apache.jena.riot.RDFFormat;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;

import com.ebremer.lws.authn.config.ServerSettings;
import com.ebremer.lws.authn.net.OutboundHttp;
import com.ebremer.lws.authn.openid.LWSConstants;
import com.ebremer.lws.authn.openid.cid.ControlledIdentifierDocument;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;

/**
 * R-44. The OpenID verifier's rules that are decided <em>after</em> something is fetched — the subject's
 * controlled identifier document, OpenID Connect Discovery, the JWK set, the signature, the validity
 * window and the relying-party checks — each with a test that fails if the rule is deleted.
 *
 * <p>A local server plays both the subject's host and a third-party OpenID Provider, and a session whose
 * only provider is a JDK RS256 verifier stands in for Keycloak's. Every case starts from a credential that
 * verifies ({@link #aCorrectCredentialVerifies}) and changes one thing, so a refusal can only be the rule
 * under test. Each test has its own issuer and subject paths, so the document cache cannot carry one
 * test's answer into another.</p>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OpenIdVerifierRulesTest {

    private static final String ALLOWLIST_PROPERTY = "lws.authn.allowedInternalHosts";
    private static final String CLIENT = "https://client.example/app";
    private static final String KID = "op-key-1";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private record Route(int status, String contentType, String body) {
    }

    private final Map<String, Route> routes = new ConcurrentHashMap<>();
    private final AtomicInteger fixtures = new AtomicInteger();
    private HttpServer server;
    private int port;
    private String previousAllowlist;
    private KeyPair opKey;

    @BeforeAll
    void startServer() throws Exception {
        previousAllowlist = System.getProperty(ALLOWLIST_PROPERTY);
        System.setProperty(ALLOWLIST_PROPERTY, "localhost");
        // The allow-list is read lazily only while no provider has contributed one: start from that.
        ServerSettings.reset();
        opKey = rsa();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        port = server.getAddress().getPort();
        server.createContext("/", exchange -> {
            Route route = routes.getOrDefault(exchange.getRequestURI().getPath(),
                    new Route(404, "text/plain", "not found"));
            byte[] body = route.body().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", route.contentType());
            exchange.sendResponseHeaders(route.status(), body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
    }

    @BeforeEach
    void forgetFetches() {
        OutboundHttp.resetCircuits();
        OutboundHttp.clearCache();
    }

    @AfterAll
    void stopServer() {
        server.stop(0);
        if (previousAllowlist == null) {
            System.clearProperty(ALLOWLIST_PROPERTY);
        } else {
            System.setProperty(ALLOWLIST_PROPERTY, previousAllowlist);
        }
        ServerSettings.reset();
        OutboundHttp.resetCircuits();
        OutboundHttp.clearCache();
    }

    // ------------------------------------------------------------------------------- fixtures

    /**
     * An OpenID Provider and one subject it vouches for, at paths no other test uses: discovery, a JWK
     * set holding {@link #opKey}, and the subject's document — the one this provider's own {@code cid}
     * endpoint would serve — as Turtle.
     */
    private final class Fixture {
        final String iss;
        final String sub;
        private final String opPath;
        private final String subPath;

        Fixture() throws Exception {
            int n = fixtures.incrementAndGet();
            opPath = "/op-" + n;
            subPath = "/cid-" + n;
            iss = "http://localhost:" + port + opPath;
            sub = "http://localhost:" + port + subPath;
            discovery(200, Map.of("issuer", iss, "jwks_uri", iss + "/jwks",
                    "id_token_signing_alg_values_supported", List.of("RS256")));
            jwks(200, jwkSet(opKey.getPublic()));
            document(LWSConstants.TURTLE, new ControlledIdentifierDocument(sub, iss).toRdf(RDFFormat.TURTLE));
        }

        Fixture document(String contentType, String body) {
            return document(200, contentType, body);
        }

        Fixture document(int status, String contentType, String body) {
            routes.put(subPath, new Route(status, contentType, body.replace("SUB", sub).replace("ISS", iss)));
            return this;
        }

        Fixture discovery(int status, Map<String, Object> configuration) throws Exception {
            routes.put(opPath + "/.well-known/openid-configuration",
                    new Route(status, "application/json", JSON.writeValueAsString(configuration)));
            return this;
        }

        Fixture jwks(int status, String body) {
            routes.put(opPath + "/jwks", new Route(status, "application/json", body));
            return this;
        }

        /** Claims that verify: {@code azp} and {@code aud} the client, issued now, valid for five minutes. */
        Map<String, Object> claims() {
            long now = Instant.now().getEpochSecond();
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("iss", iss);
            claims.put("sub", sub);
            claims.put("azp", CLIENT);
            claims.put("aud", List.of(CLIENT));
            claims.put("iat", now);
            claims.put("exp", now + 300);
            return claims;
        }

        /** An ID Token from this OP, signed with its key, with {@code edit} applied to the claims first. */
        String idToken(Consumer<Map<String, Object>> edit) throws Exception {
            Map<String, Object> claims = claims();
            edit.accept(claims);
            return sign(claims, opKey.getPrivate());
        }

        String idToken() throws Exception {
            return idToken(claims -> { });
        }
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String jwkSet(PublicKey key) throws Exception {
        RSAPublicKey rsa = (RSAPublicKey) key;
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("kid", KID);
        jwk.put("use", "sig");
        jwk.put("alg", "RS256");
        jwk.put("n", B64.encodeToString(unsigned(rsa.getModulus())));
        jwk.put("e", B64.encodeToString(unsigned(rsa.getPublicExponent())));
        return JSON.writeValueAsString(Map.of("keys", List.of(jwk)));
    }

    private static byte[] unsigned(java.math.BigInteger value) {
        byte[] bytes = value.toByteArray();
        return bytes[0] == 0 ? java.util.Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    private static String sign(Map<String, Object> claims, PrivateKey key) throws Exception {
        String input = B64.encodeToString(JSON.writeValueAsBytes(Map.of("alg", "RS256", "typ", "JWT", "kid", KID)))
                + "." + B64.encodeToString(JSON.writeValueAsBytes(claims));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(key);
        signature.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + B64.encodeToString(signature.sign());
    }

    /** A session whose RS256 signature provider is the JDK's; nothing else is offered, or needed. */
    private static KeycloakSession rs256Session() {
        Object provider = Proxy.newProxyInstance(OpenIdVerifierRulesTest.class.getClassLoader(),
                new Class<?>[]{SignatureProvider.class}, (proxy, method, args) -> {
                    if ("verifier".equals(method.getName()) && args != null && args[0] instanceof KeyWrapper key) {
                        return new SignatureVerifierContext() {
                            @Override
                            public String getKid() {
                                return key.getKid();
                            }

                            @Override
                            public String getAlgorithm() {
                                return "RS256";
                            }

                            @Override
                            public boolean verify(byte[] data, byte[] signature) {
                                try {
                                    Signature verifier = Signature.getInstance("SHA256withRSA");
                                    verifier.initVerify((PublicKey) key.getPublicKey());
                                    verifier.update(data);
                                    return verifier.verify(signature);
                                } catch (Exception e) {
                                    return false;
                                }
                            }
                        };
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        return (KeycloakSession) Proxy.newProxyInstance(OpenIdVerifierRulesTest.class.getClassLoader(),
                new Class<?>[]{KeycloakSession.class}, (proxy, method, args) -> {
                    if ("getProvider".equals(method.getName()) && args != null && args.length == 2) {
                        return "RS256".equals(args[1]) ? provider : null;
                    }
                    if ("getProvider".equals(method.getName())) {
                        return null; // no truststore: the JVM's, for a client built from this session
                    }
                    if ("hashCode".equals(method.getName())) {
                        return System.identityHashCode(proxy);
                    }
                    // getContext() among them: the caller's address is then "unknown", as in a test it is.
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static VerificationResult verify(String jwt) {
        return verify(jwt, null, null);
    }

    private static VerificationResult verify(String jwt, String clientId, String audience) {
        return new LWSCredentialVerifier(rs256Session()).verify(jwt, clientId, audience);
    }

    private static void assertRefusedBy(VerificationResult result, String check) {
        assertFalse(result.isValid(), () -> check + ": " + result.getChecks());
        assertEquals(Boolean.FALSE, result.getChecks().get(check), () -> result.getErrors() + " " + result.getChecks());
    }

    private static void assertValid(VerificationResult result) {
        assertTrue(result.isValid(), () -> result.getErrors() + " " + result.getChecks());
        assertFalse(result.getChecks().containsValue(Boolean.FALSE), () -> String.valueOf(result.getChecks()));
    }

    // ------------------------------------------------------------------------------- baseline

    /** What every other case changes one thing about: a credential that verifies, all the way through. */
    @Test
    void aCorrectCredentialVerifies() throws Exception {
        Fixture op = new Fixture();
        VerificationResult result = verify(op.idToken(), CLIENT, CLIENT);
        assertValid(result);
        for (String check : new String[]{"subjectDereferenced", "subjectIdMatches", "openIdProviderServiceLocated",
                "issuerDiscoveryMatches", "algorithmAdvertised", "jwksResolved", "signatureValid", "notExpired",
                "audienceContainsClient", "authorizedPartyMatchesClient", "audienceMatched"}) {
            assertEquals(Boolean.TRUE, result.getChecks().get(check), check);
        }
        assertEquals(op.sub, result.getSubject());
        assertEquals(op.iss, result.getIssuer());
    }

    // ------------------------------------------------------------------------- the signature

    /**
     * R-44, {@code signatureValid}. The suite: the ID Token "MUST be validated as described by OpenID
     * Connect Core Section 3.1.3.7", whose step 6 validates the signature "using the keys provided by the
     * Issuer". A token whose claims were changed after signing — here, a longer life — must not verify.
     */
    @Test
    void aTokenChangedAfterSigningIsRefused() throws Exception {
        Fixture op = new Fixture();
        String[] parts = op.idToken().split("\\.");
        Map<String, Object> extended = op.claims();
        extended.put("exp", Instant.now().getEpochSecond() + 86_400);
        String tampered = parts[0] + "." + B64.encodeToString(JSON.writeValueAsBytes(extended)) + "." + parts[2];
        assertRefusedBy(verify(tampered), "signatureValid");
    }

    /** R-44, {@code signatureValid}: signed by a key the issuer did not publish, under the issuer's kid. */
    @Test
    void aTokenSignedWithAnotherKeyIsRefused() throws Exception {
        Fixture op = new Fixture();
        assertRefusedBy(verify(sign(op.claims(), rsa().getPrivate())), "signatureValid");
    }

    /** R-44, {@code signatureValid}: one flipped bit in the signature itself. */
    @Test
    void aCorruptedSignatureIsRefused() throws Exception {
        Fixture op = new Fixture();
        String jwt = op.idToken();
        int dot = jwt.lastIndexOf('.');
        byte[] signature = Base64.getUrlDecoder().decode(jwt.substring(dot + 1));
        signature[signature.length / 2] ^= 0x01;
        assertRefusedBy(verify(jwt.substring(0, dot + 1) + B64.encodeToString(signature)), "signatureValid");
    }

    // ----------------------------------------------------------------------- validity window

    /**
     * R-44, {@code notExpired}. Core §3.1.3.7 step 9: "The current time MUST be before the time
     * represented by the exp Claim". Correctly signed, issued two hours ago, expired one hour ago.
     */
    @Test
    void anExpiredTokenIsRefused() throws Exception {
        Fixture op = new Fixture();
        long now = Instant.now().getEpochSecond();
        VerificationResult result = verify(op.idToken(claims -> {
            claims.put("iat", now - 7200);
            claims.put("exp", now - 3600);
        }));
        assertRefusedBy(result, "notExpired");
        assertEquals(Boolean.TRUE, result.getChecks().get("signatureValid"), "refused for its age, not its signature");
    }

    /**
     * R-44, {@code notExpired}. Core §2 makes {@code exp} REQUIRED; Keycloak's {@code isActive()} reads a
     * missing one as "never expires", so a captured token would be replayable for ever.
     */
    @Test
    void aTokenWithoutExpiryIsRefused() throws Exception {
        Fixture op = new Fixture();
        VerificationResult result = verify(op.idToken(claims -> claims.remove("exp")));
        assertRefusedBy(result, "notExpired");
        assertTrue(result.getErrors().toString().contains("missing the required 'exp'"), result.getErrors().toString());
    }

    /** R-44, {@code notExpired}: an {@code nbf} beyond the clock skew is not yet valid. */
    @Test
    void aTokenNotYetValidIsRefused() throws Exception {
        Fixture op = new Fixture();
        long now = Instant.now().getEpochSecond();
        VerificationResult result = verify(op.idToken(claims -> {
            claims.put("nbf", now + 600);
            claims.put("exp", now + 900);
        }));
        assertRefusedBy(result, "notExpired");
    }

    // ------------------------------------------------------------- the subject's document

    /**
     * R-44, {@code subjectDereferenced}. The suite requires "a valid controlled identifier document"; an
     * error status is not one, whatever its body says. (Held twice: {@code OutboundHttp} never reads an
     * error body either. The error names the status problem, so deleting the verifier's own check — and
     * failing later, on the missing body, as "failed to dereference" — still fails this test.)
     */
    @Test
    void aSubjectThatDoesNotAnswer200IsRefused() throws Exception {
        for (int status : new int[]{404, 410, 500}) {
            Fixture op = new Fixture();
            op.document(status, LWSConstants.TURTLE, new ControlledIdentifierDocument(op.sub, op.iss).toRdf(RDFFormat.TURTLE));
            VerificationResult result = verify(op.idToken());
            assertRefusedBy(result, "subjectDereferenced");
            assertNull(result.getChecks().get("subjectIdMatches"), "not read: " + status);
            assertTrue(result.getErrors().toString().contains("did not return a controlled identifier document"),
                    status + ": " + result.getErrors());
        }
    }

    /**
     * R-44, {@code subjectDereferenced}. A document served as a type that is not an RDF syntax this
     * verifier reads is refused as that, and the error says which type it was — even when the body would
     * have verified. A JSON-LD body is the case that matters: with no declared type a leading brace is
     * read as JSON-LD, and a declared wrong type must not be rescued by that sniff.
     */
    @Test
    void aSubjectServedAsAnUnsupportedTypeIsRefused() throws Exception {
        for (String type : new String[]{"text/html", "text/plain", "application/octet-stream"}) {
            for (boolean jsonLd : new boolean[]{false, true}) {
                Fixture op = new Fixture();
                ControlledIdentifierDocument document = new ControlledIdentifierDocument(op.sub, op.iss);
                op.document(type, jsonLd ? document.toJsonLd() : document.toRdf(RDFFormat.TURTLE));
                VerificationResult result = verify(op.idToken());
                assertRefusedBy(result, "subjectDereferenced");
                assertTrue(result.getErrors().toString().contains(type), type + ": " + result.getErrors());
            }
        }
    }

    /**
     * R-44, {@code subjectIdMatches}, on the Turtle path. The suite requires "a controlled identifier
     * document with an {@code id} value equal to the subject identifier"; RDF has no topmost map, so the
     * graph must at least describe the subject. This one declares the issuer — for somebody else.
     */
    @Test
    void aTurtleDocumentAboutSomebodyElseIsRefused() throws Exception {
        Fixture op = new Fixture();
        op.document(LWSConstants.TURTLE,
                new ControlledIdentifierDocument("https://other.example/agent", op.iss).toRdf(RDFFormat.TURTLE));
        VerificationResult result = verify(op.idToken());
        assertRefusedBy(result, "subjectIdMatches");
        assertEquals(Boolean.TRUE, result.getChecks().get("subjectDereferenced"), "fetched and read");
    }

    /** R-44, {@code subjectIdMatches}, through the compact reader: the topmost {@code id} is not the subject. */
    @Test
    void aCompactDocumentAboutSomebodyElseIsRefused() throws Exception {
        Fixture op = new Fixture();
        op.document(LWSConstants.JSON_LD, COMPACT.replace("\"id\":\"SUB\"", "\"id\":\"https://other.example/agent\""));
        assertRefusedBy(verify(op.idToken()), "subjectIdMatches");
    }

    // ------------------------------------------------------------- the provider service

    /**
     * R-44, {@code openIdProviderServiceLocated}. The suite: the document "MUST include a service entry
     * with type {@code https://www.w3.org/ns/lws#OpenIdProvider}" whose {@code serviceEndpoint} "MUST
     * equal the issuer". The type is right; the endpoint is another issuer's — and, compared as Core
     * §3.1.3.7 step 2 compares issuers ("MUST exactly match"), one trailing slash away from this one.
     */
    @Test
    void aServiceForAnotherIssuerIsRefused() throws Exception {
        for (String endpoint : new String[]{"https://other-op.example/realms/x", "ISS/"}) {
            Fixture op = new Fixture();
            op.document(LWSConstants.TURTLE,
                    new ControlledIdentifierDocument(op.sub, endpoint.replace("ISS", op.iss)).toRdf(RDFFormat.TURTLE));
            VerificationResult result = verify(op.idToken());
            assertRefusedBy(result, "openIdProviderServiceLocated");
            assertEquals(Boolean.TRUE, result.getChecks().get("subjectIdMatches"), endpoint);
        }
    }

    /**
     * R-44, {@code openIdProviderServiceLocated}: the document is about the subject, and declares the
     * right service with the right endpoint — as a service of a different node.
     */
    @Test
    void aServiceDeclaredForAnotherNodeIsRefused() throws Exception {
        Fixture op = new Fixture();
        op.document(LWSConstants.TURTLE, "<SUB> <http://xmlns.com/foaf/0.1/name> \"Alice\" .\n"
                + "<https://other.example/agent> <" + LWSConstants.DID_SERVICE + "> <SUB#op> .\n"
                + "<SUB#op> a <" + LWSConstants.OPENID_PROVIDER_TYPE + "> ; <"
                + LWSConstants.DID_SERVICE_ENDPOINT + "> <ISS> .\n");
        VerificationResult result = verify(op.idToken());
        assertRefusedBy(result, "openIdProviderServiceLocated");
        assertEquals(Boolean.TRUE, result.getChecks().get("subjectIdMatches"));
    }

    // --------------------------------------------------- JSON-LD: the processor, and the fallback

    /** A compact document naming a context this provider does not bundle, so the processor declines it. */
    private static final String COMPACT = "{\"@context\":[\"" + LWSConstants.CID_CONTEXT
            + "\",\"https://context.example/not-bundled/v1\"],\"id\":\"SUB\",\"service\":[{\"id\":\"SUB#op\","
            + "\"type\":\"" + LWSConstants.OPENID_PROVIDER_TYPE + "\",\"serviceEndpoint\":\"ISS\"}]}";

    /**
     * R-44. The JSON-LD processor's path, all the way to a valid result: the document this provider's own
     * {@code cid} endpoint serves as {@code application/ld+json}. Every other OpenID test reads Turtle.
     */
    @Test
    void aJsonLdDocumentVerifiesThroughTheProcessor() throws Exception {
        Fixture op = new Fixture();
        op.document(LWSConstants.JSON_LD, new ControlledIdentifierDocument(op.sub, op.iss).toJsonLd());
        assertValid(verify(op.idToken()));
    }

    /** R-44. And the processor's reading is not permissive: another issuer's service is refused there too. */
    @Test
    void theProcessorRefusesAServiceForAnotherIssuer() throws Exception {
        Fixture op = new Fixture();
        op.document(LWSConstants.JSON_LD,
                new ControlledIdentifierDocument(op.sub, "https://other-op.example/realms/x").toJsonLd());
        assertRefusedBy(verify(op.idToken()), "openIdProviderServiceLocated");
    }

    /**
     * R-44. The compact fallback, all the way to a valid result: a document whose extra context this
     * provider does not bundle is read by name, which is the only reading available without it.
     */
    @Test
    void aCompactDocumentVerifiesThroughTheFallback() throws Exception {
        Fixture op = new Fixture();
        op.document(LWSConstants.JSON_LD, COMPACT);
        assertValid(verify(op.idToken()));
    }

    /** R-44. The fallback refuses another issuer's service as the processor does. */
    @Test
    void theFallbackRefusesAServiceForAnotherIssuer() throws Exception {
        Fixture op = new Fixture();
        op.document(LWSConstants.JSON_LD, COMPACT.replace("\"serviceEndpoint\":\"ISS\"",
                "\"serviceEndpoint\":\"https://other-op.example/realms/x\""));
        assertRefusedBy(verify(op.idToken()), "openIdProviderServiceLocated");
    }

    /** R-44. Nor does the fallback take a service whose type is not the OpenID Provider type. */
    @Test
    void theFallbackRefusesAServiceOfAnotherType() throws Exception {
        Fixture op = new Fixture();
        op.document(LWSConstants.JSON_LD, COMPACT.replace("\"type\":\"" + LWSConstants.OPENID_PROVIDER_TYPE + "\"",
                "\"type\":\"https://type.example/Other\""));
        assertRefusedBy(verify(op.idToken()), "openIdProviderServiceLocated");
    }

    // ---------------------------------------------------------------------------- discovery

    /**
     * R-44, {@code jwksResolved}. Core §3.1.3.7 step 6 verifies with "the keys provided by the Issuer",
     * which this verifier finds by OpenID Connect Discovery; an issuer whose configuration cannot be read
     * has provided none. The error names the status, so the check is pinned even though a missing error
     * body would fail later anyway.
     */
    @Test
    void anIssuerWhoseDiscoveryDoesNotAnswer200IsRefused() throws Exception {
        for (int status : new int[]{404, 500}) {
            Fixture op = new Fixture();
            op.discovery(status, Map.of("issuer", op.iss, "jwks_uri", op.iss + "/jwks"));
            VerificationResult result = verify(op.idToken());
            assertRefusedBy(result, "jwksResolved");
            assertNull(result.getChecks().get("issuerDiscoveryMatches"), "not read: " + status);
            assertNull(result.getChecks().get("signatureValid"));
            assertTrue(result.getErrors().toString().contains("did not return a configuration document"),
                    status + ": " + result.getErrors());
        }
    }

    /**
     * R-44, {@code issuerDiscoveryMatches}. Discovery 1.0 §4.3: the {@code issuer} returned "MUST be
     * identical to the Issuer URL that was used as the prefix to {@code /.well-known/openid-configuration}".
     */
    @Test
    void aConfigurationForAnotherIssuerIsRefused() throws Exception {
        Fixture op = new Fixture();
        op.discovery(200, Map.of("issuer", "https://other-op.example/realms/x", "jwks_uri", op.iss + "/jwks"));
        assertRefusedBy(verify(op.idToken()), "issuerDiscoveryMatches");
    }

    /**
     * R-44, {@code algorithmAdvertised}. Discovery 1.0 §3: {@code id_token_signing_alg_values_supported}
     * lists "the JWS signing algorithms (alg values) supported by the OP for the ID Token".
     */
    @Test
    void anAlgorithmTheIssuerDoesNotAdvertiseIsRefused() throws Exception {
        Fixture op = new Fixture();
        op.discovery(200, Map.of("issuer", op.iss, "jwks_uri", op.iss + "/jwks",
                "id_token_signing_alg_values_supported", List.of("ES256")));
        assertRefusedBy(verify(op.idToken()), "algorithmAdvertised");
    }

    /** R-44, {@code jwksResolved}: a configuration without a {@code jwks_uri}, and a JWK set that does not answer 200. */
    @Test
    void anIssuerWhoseKeysCannotBeReadIsRefused() throws Exception {
        Fixture noUri = new Fixture();
        noUri.discovery(200, Map.of("issuer", noUri.iss));
        assertRefusedBy(verify(noUri.idToken()), "jwksResolved");

        Fixture noSet = new Fixture();
        noSet.jwks(500, jwkSet(opKey.getPublic()));
        VerificationResult result = verify(noSet.idToken());
        assertRefusedBy(result, "jwksResolved");
        assertTrue(result.getErrors().toString().contains("could not be retrieved"), result.getErrors().toString());
    }

    // ------------------------------------------------------------------------- relying party

    /**
     * R-44, {@code authorizedPartyMatchesClient}. With the expected client in {@code aud}, an {@code azp}
     * naming a different party is refused: the token was issued for that party (Core §2, "the party to
     * which the ID Token was issued"), and the suite makes {@code azp} the LWS client identifier.
     */
    @Test
    void anAuthorizedPartyOtherThanTheClientIsRefused() throws Exception {
        Fixture op = new Fixture();
        VerificationResult result = verify(op.idToken(claims -> {
            claims.put("azp", "https://other-client.example/app");
            claims.put("aud", List.of(CLIENT, "https://other-client.example/app"));
        }), CLIENT, null);
        assertRefusedBy(result, "authorizedPartyMatchesClient");
        assertEquals(Boolean.TRUE, result.getChecks().get("audienceContainsClient"), "aud was right");
    }

    /** R-44, {@code audienceContainsClient}. Core §3.1.3.7 step 3: {@code aud} "MUST contain" the client. */
    @Test
    void anAudienceWithoutTheClientIsRefused() throws Exception {
        Fixture op = new Fixture();
        VerificationResult result = verify(op.idToken(claims -> claims.put("aud", List.of("https://other-client.example/app"))),
                CLIENT, null);
        assertRefusedBy(result, "audienceContainsClient");
    }

    /** R-44, {@code audienceMatched}: a credential not restricted to the authorization server verifying it. */
    @Test
    void anAudienceWithoutTheAuthorizationServerIsRefused() throws Exception {
        Fixture op = new Fixture();
        assertRefusedBy(verify(op.idToken(), null, "https://as.example"), "audienceMatched");
    }
}
