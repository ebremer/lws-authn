/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.openid.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;

import com.ebremer.lws.authn.config.ServerSettings;
import com.ebremer.lws.authn.net.OutboundHttp;
import com.ebremer.lws.authn.openid.LWSConstants;
import com.ebremer.lws.authn.rdf.RdfParsing;
import com.ebremer.lws.authn.testsupport.SelfIssuedJwts;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;

/**
 * The OpenID Connect suite's own examples, as published in the Working Draft of 15 October 2026
 * (https://www.w3.org/TR/2026/WD-lws10-authn-openid-20261015/, Examples 1 and 2; unchanged in the
 * editor's draft of 9 November 2026), run through the verifier.
 *
 * <p>Example 1's header and payload are the JWS's own bytes, whitespace and member order included, and
 * Example 2 is the document the subject's server answers with — a service with no {@code id}, unlike the
 * documents this provider serves. What changes:</p>
 *
 * <ul>
 *   <li>the two hosts the verifier fetches from — the subject's, {@code https://id.example}, and the
 *       OpenID Provider's, {@code https://openid.example} — are a local server, so their URLs are
 *       {@code http://localhost:<port>/id.example/…} and {@code …/openid.example}, the same in the token
 *       and in the document. The client {@code https://client.example/17da1b} and the authorization
 *       server {@code https://as.example} are compared, never fetched, and stay as printed;</li>
 *   <li>the OpenID Provider is real: OpenID Connect Discovery answers with an {@code issuer}, a
 *       {@code jwks_uri} and ES256 as its ID Token algorithm, and its JWK set holds the P-256 key, under
 *       the example's {@code kid}, that signs the token;</li>
 *   <li>{@code iat} and {@code exp} move from October 2025 to now, five minutes apart as printed —
 *       {@link #theExampleAsPrintedFailsOnlyForItsDates} shows that is all that moving them changes.</li>
 * </ul>
 *
 * <p>A session whose ES256 provider is the JDK's stands in for Keycloak's, as {@link OpenIdVerifierRulesTest}'s
 * RS256 one does; {@code LwsAuthIT} verifies through Keycloak's own.</p>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OpenIdSpecificationExampleTest {

    private static final String ALLOWLIST_PROPERTY = "lws.authn.allowedInternalHosts";
    private static final String CLIENT = "https://client.example/17da1b";
    private static final String AUTHORIZATION_SERVER = "https://as.example";
    private static final String KID = "12dbe73a";
    private static final ObjectMapper JSON = new ObjectMapper();

    /** Example 1's JOSE header, as printed. */
    private static final String HEADER = """
            {
              "typ": "JWT",
              "kid": "12dbe73a",
              "kty": "EC",
              "alg": "ES256",
              "crv": "P-256"
            }""";

    /** Example 1's payload, as printed: {@code IAT} and {@code EXP} stand for its two dates. */
    private static final String PAYLOAD = """
            {
              "sub": "https://id.example/end-user",
              "iss": "https://openid.example",
              "azp": "https://client.example/17da1b",
              "aud": ["https://client.example/17da1b", "https://as.example"],
              "iat": IAT,
              "exp": EXP
            }""";

    private static final long EXAMPLE_IAT = 1761313600L;
    private static final long EXAMPLE_EXP = 1761313900L;

    /** Example 2, the end-user's controlled identifier document, as printed. */
    private static final String DOCUMENT = """
            {
                "@context": [
                    "https://www.w3.org/ns/cid/v1"
                ],
                "id": "https://id.example/end-user",
                "service": [{
                    "type": "https://www.w3.org/ns/lws#OpenIdProvider",
                    "serviceEndpoint": "https://openid.example"
                }]
            }""";

    private record Route(String contentType, String body) {
    }

    private final Map<String, Route> routes = new ConcurrentHashMap<>();
    private HttpServer server;
    private String previousAllowlist;
    private KeyPair opKey;
    private String subjectHost;
    private String providerHost;

    @BeforeAll
    void startServer() throws Exception {
        // Keycloak initializes this at boot; the JWK set's EC key cannot be built without it.
        CryptoIntegration.init(OpenIdSpecificationExampleTest.class.getClassLoader());
        previousAllowlist = System.getProperty(ALLOWLIST_PROPERTY);
        System.setProperty(ALLOWLIST_PROPERTY, "localhost");
        ServerSettings.reset();
        opKey = SelfIssuedJwts.ec("secp256r1");
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String base = "http://localhost:" + server.getAddress().getPort();
        subjectHost = base + "/id.example";
        providerHost = base + "/openid.example";
        server.createContext("/", exchange -> {
            Route route = routes.get(exchange.getRequestURI().getPath());
            byte[] body = (route == null ? "not found" : route.body()).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", route == null ? "text/plain" : route.contentType());
            exchange.sendResponseHeaders(route == null ? 404 : 200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();

        Map<String, Object> jwk = new LinkedHashMap<>(SelfIssuedJwts.publicJwk(opKey.getPublic()));
        jwk.put("kid", KID);
        jwk.put("use", "sig");
        jwk.put("alg", "ES256");
        routes.put("/openid.example/.well-known/openid-configuration", new Route("application/json",
                JSON.writeValueAsString(Map.of("issuer", providerHost, "jwks_uri", providerHost + "/jwks",
                        "id_token_signing_alg_values_supported", List.of("ES256")))));
        routes.put("/openid.example/jwks", new Route("application/json",
                JSON.writeValueAsString(Map.of("keys", List.of(jwk)))));
        serveDocument(LWSConstants.JSON_LD);
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

    /** The example's two fetched hosts, mapped to the local server. */
    private String localized(String text) {
        return text.replace("https://id.example", subjectHost).replace("https://openid.example", providerHost);
    }

    private void serveDocument(String contentType) {
        routes.put("/id.example/end-user", new Route(contentType, localized(DOCUMENT)));
    }

    /** Example 1 with these dates, signed by the OpenID Provider's key: ES256, R‖S as RFC 7518 §3.4 has it. */
    private String example(long iat, long exp) throws Exception {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String payload = localized(PAYLOAD).replace("IAT", Long.toString(iat)).replace("EXP", Long.toString(exp));
        String input = b64.encodeToString(HEADER.getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        Signature signature = Signature.getInstance("SHA256withECDSAinP1363Format");
        signature.initSign(opKey.getPrivate());
        signature.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + b64.encodeToString(signature.sign());
    }

    private String currentExample() throws Exception {
        long now = Instant.now().getEpochSecond();
        return example(now, now + (EXAMPLE_EXP - EXAMPLE_IAT));
    }

    private static VerificationResult verify(String jwt, String clientId, String audience) {
        return new LWSCredentialVerifier(es256Session()).verify(jwt, clientId, audience);
    }

    private static Map<String, Boolean> failed(VerificationResult result) {
        Map<String, Boolean> failed = new LinkedHashMap<>(result.getChecks());
        failed.values().removeIf(Boolean.TRUE::equals);
        return failed;
    }

    /**
     * Example 1, signed, verifies against Example 2 — served as JSON-LD and as CID 1.0's own media type —
     * with the relying-party checks OpenID Connect Core §3.1.3.7 adds when the caller names its client and
     * the authorization server: {@code aud} lists both, and {@code azp} is the client. Without them it
     * verifies too, and the result reports the suite's subject, issuer and client identifiers and its
     * token type identifier.
     */
    @Test
    void theExampleIdTokenVerifiesAgainstTheExampleDocument() throws Exception {
        for (String contentType : new String[]{LWSConstants.JSON_LD, RdfParsing.CID}) {
            serveDocument(contentType);
            OutboundHttp.clearCache();
            VerificationResult result = verify(currentExample(), CLIENT, AUTHORIZATION_SERVER);

            assertTrue(result.isValid(), () -> contentType + ": " + result.getErrors() + " " + result.getChecks());
            assertTrue(failed(result).isEmpty(), () -> contentType + ": " + result.getChecks());
            assertEquals(subjectHost + "/end-user", result.getSubject());
            assertEquals(providerHost, result.getIssuer());
            assertEquals(CLIENT, result.getClient());
            assertEquals(LWSConstants.TOKEN_TYPE_ID_TOKEN, result.getTokenType());
            for (String check : new String[]{"signingAlgorithmNotNone", "subjectIdMatches",
                    "openIdProviderServiceLocated", "issuerDiscoveryMatches", "algorithmAdvertised", "jwksResolved",
                    "algorithmMatchesKey", "signatureValid", "notExpired", "issuedAtPresent", "audiencePresent",
                    "audienceContainsClient", "authorizedPartyMatchesClient", "audienceMatched"}) {
                assertEquals(Boolean.TRUE, result.getChecks().get(check), contentType + ": " + check);
            }
        }
        serveDocument(LWSConstants.JSON_LD);
        OutboundHttp.clearCache();
        VerificationResult unbound = verify(currentExample(), null, null);
        assertTrue(unbound.isValid(), () -> unbound.getErrors() + " " + unbound.getChecks());
    }

    /**
     * Example 1 with its own dates is a correctly signed ID Token that expired in October 2025:
     * {@code notExpired} is the one check that fails.
     */
    @Test
    void theExampleAsPrintedFailsOnlyForItsDates() throws Exception {
        VerificationResult result = verify(example(EXAMPLE_IAT, EXAMPLE_EXP), CLIENT, AUTHORIZATION_SERVER);

        assertFalse(result.isValid());
        assertEquals(Map.of("notExpired", false), failed(result), () -> result.getErrors().toString());
        assertEquals(Boolean.TRUE, result.getChecks().get("signatureValid"));
    }

    /** The example's {@code aud} names {@code https://as.example}; for another authorization server it is not valid. */
    @Test
    void theExampleIdTokenIsNotValidForAnotherAuthorizationServer() throws Exception {
        VerificationResult result = verify(currentExample(), CLIENT, "https://other-as.example");

        assertFalse(result.isValid());
        assertEquals(Map.of("audienceMatched", false), failed(result), () -> result.getErrors().toString());
    }

    /** Nor for another client: {@code aud} does not list it (OpenID Connect Core §3.1.3.7 step 3). */
    @Test
    void theExampleIdTokenIsNotValidForAnotherClient() throws Exception {
        VerificationResult result = verify(currentExample(), "https://client.example/other", AUTHORIZATION_SERVER);

        assertFalse(result.isValid());
        assertEquals(Map.of("audienceContainsClient", false), failed(result), () -> result.getErrors().toString());
    }

    /** A session whose ES256 signature provider is the JDK's; nothing else is offered, or needed. */
    private static KeycloakSession es256Session() {
        Object provider = Proxy.newProxyInstance(OpenIdSpecificationExampleTest.class.getClassLoader(),
                new Class<?>[]{SignatureProvider.class}, (proxy, method, args) -> {
                    if ("verifier".equals(method.getName()) && args != null && args[0] instanceof KeyWrapper key) {
                        return new SignatureVerifierContext() {
                            @Override
                            public String getKid() {
                                return key.getKid();
                            }

                            @Override
                            public String getAlgorithm() {
                                return "ES256";
                            }

                            @Override
                            public boolean verify(byte[] data, byte[] signature) {
                                try {
                                    Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
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
        return (KeycloakSession) Proxy.newProxyInstance(OpenIdSpecificationExampleTest.class.getClassLoader(),
                new Class<?>[]{KeycloakSession.class}, (proxy, method, args) -> {
                    if ("getProvider".equals(method.getName()) && args != null && args.length == 2) {
                        return "ES256".equals(args[1]) ? provider : null;
                    }
                    if ("getProvider".equals(method.getName())) {
                        return null; // no truststore: the JVM's, for a client built from this session
                    }
                    if ("hashCode".equals(method.getName())) {
                        return System.identityHashCode(proxy);
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }
}
