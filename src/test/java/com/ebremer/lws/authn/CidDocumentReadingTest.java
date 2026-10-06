/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import com.ebremer.lws.authn.did.DidKey;
import com.ebremer.lws.authn.net.OutboundHttp;
import com.ebremer.lws.authn.openid.verify.LWSCredentialVerifier;
import com.ebremer.lws.authn.openid.verify.VerificationResult;
import com.ebremer.lws.authn.ssicid.verify.SelfSignedCidVerifier;
import com.ebremer.lws.authn.ssicid.verify.SsiCidVerificationResult;
import com.ebremer.lws.authn.testsupport.SelfIssuedJwts;
import com.sun.net.httpserver.HttpServer;

/**
 * Both JWT verifiers reading a subject's controlled identifier document over HTTP, from a local server,
 * in the shapes CID 1.0 allows and the shapes it does not.
 *
 * <ul>
 *   <li><b>R-18</b> — "a valid controlled identifier document with an {@code id} value equal to the
 *       subject identifier": the topmost map's {@code id}, not "some node in the graph", and a document
 *       about somebody else is reported as that rather than as a failed fetch.</li>
 *   <li><b>R-19</b> — a document with no {@code @context} (CID 1.0 §4.2.1), one served as
 *       {@code application/cid} (Appendix A), and the compact reader's handling of arrays.</li>
 * </ul>
 *
 * <p>The OpenID verifier gets as far as OpenID Connect Discovery, which this server does not answer; the
 * checks before that are what these cases are about.</p>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CidDocumentReadingTest {

    private static final String ALLOWLIST_PROPERTY = "lws.authn.allowedInternalHosts";
    private static final String LWS_OPENID_PROVIDER = "https://www.w3.org/ns/lws#OpenIdProvider";
    private static final String CID_CONTEXT = "\"@context\":\"https://www.w3.org/ns/cid/v1\",";
    private static final String UNBUNDLED_CONTEXT =
            "\"@context\":[\"https://www.w3.org/ns/cid/v1\",\"https://context.example/not-bundled/v1\"],";

    private final Map<String, String[]> routes = new ConcurrentHashMap<>();
    private final AtomicInteger paths = new AtomicInteger();
    private HttpServer server;
    private int port;
    private String previousAllowlist;

    @BeforeAll
    void startServer() throws IOException {
        previousAllowlist = System.getProperty(ALLOWLIST_PROPERTY);
        System.setProperty(ALLOWLIST_PROPERTY, "localhost");
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        port = server.getAddress().getPort();
        server.createContext("/", exchange -> {
            String[] route = routes.get(exchange.getRequestURI().getPath());
            byte[] body = (route == null ? "not found" : route[1]).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", route == null ? "text/plain" : route[0]);
            exchange.sendResponseHeaders(route == null ? 404 : 200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
    }

    @AfterAll
    void stopServer() {
        server.stop(0);
        if (previousAllowlist == null) {
            System.clearProperty(ALLOWLIST_PROPERTY);
        } else {
            System.setProperty(ALLOWLIST_PROPERTY, previousAllowlist);
        }
        OutboundHttp.resetCircuits();
    }

    /** Serves {@code document} — with {@code SUB} replaced by its own URL — and returns that URL. */
    private String serve(String contentType, String document) {
        String path = "/cid-" + paths.incrementAndGet();
        String sub = "http://localhost:" + port + path;
        routes.put(path, new String[]{contentType, document.replace("SUB", sub)});
        return sub;
    }

    // ------------------------------------------------------------------------- self-signed CID

    private record SelfSigned(String sub, SsiCidVerificationResult result) {
    }

    /** {@code document} may use {@code SUB} and {@code KEY} (an Ed25519 Multikey that signs the credential). */
    private SelfSigned selfSigned(String contentType, String document) throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String key = DidKey.multibaseValue(DidKey.encodeEd25519(pair.getPublic()));
        String sub = serve(contentType, document.replace("KEY", key));
        String jwt = SelfIssuedJwts.sign(SelfIssuedJwts.claims(sub), "EdDSA", sub + "#k1", pair.getPrivate(), "Ed25519");
        return new SelfSigned(sub, new SelfSignedCidVerifier(null).verify(jwt, SelfIssuedJwts.AUDIENCE));
    }

    private static final String MULTIKEY_METHOD =
            "{\"id\":\"SUB#k1\",\"type\":\"Multikey\",\"controller\":\"SUB\",\"publicKeyMultibase\":\"KEY\"}";

    /** CID 1.0 §4.2.1: a document need not carry a context; a consumer injects the CID one. */
    private static final String CONTEXTLESS_SELF_SIGNED =
            "{\"id\":\"SUB\",\"verificationMethod\":[" + MULTIKEY_METHOD + "],\"authentication\":[\"SUB#k1\"]}";

    @Test
    void selfSignedADocumentWithoutAContextVerifies() throws Exception {
        for (String type : new String[]{"application/ld+json", "application/cid", "application/json"}) {
            SsiCidVerificationResult result = selfSigned(type, CONTEXTLESS_SELF_SIGNED).result();
            assertTrue(result.isValid(), type + ": " + result.getErrors() + " " + result.getChecks());
        }
    }

    @Test
    void selfSignedAnApplicationCidDocumentVerifies() throws Exception {
        SsiCidVerificationResult result = selfSigned("application/cid",
                "{" + CID_CONTEXT + "\"id\":\"SUB\",\"authentication\":[" + MULTIKEY_METHOD + "]}").result();
        assertTrue(result.isValid(), result.getErrors() + " " + result.getChecks());
    }

    /**
     * R-18. The topmost id is somebody else's; the subject is only a node nested under
     * {@code alsoKnownAs}. In RDF that node "has the subject as its subject", which is all that used to be
     * asked — and its authentication method verified the credential.
     */
    @Test
    void selfSignedADocumentAboutSomebodyElseIsNotTheSubjectsDocument() throws Exception {
        SsiCidVerificationResult result = selfSigned("application/ld+json", "{" + CID_CONTEXT
                + "\"id\":\"https://other.example/doc\",\"alsoKnownAs\":[{\"id\":\"SUB\",\"authentication\":["
                + MULTIKEY_METHOD + "]}]}").result();
        assertFalse(result.isValid());
        assertEquals(Boolean.TRUE, result.getChecks().get("subjectDereferenced"), "it was fetched and read");
        assertEquals(Boolean.FALSE, result.getChecks().get("subjectIdMatches"), String.valueOf(result.getChecks()));
    }

    @Test
    void selfSignedAGraphWithNoTopmostIdIsNotTheSubjectsDocument() throws Exception {
        SsiCidVerificationResult result = selfSigned("application/ld+json", "{" + CID_CONTEXT
                + "\"@graph\":[{\"id\":\"SUB\",\"authentication\":[" + MULTIKEY_METHOD + "]}]}").result();
        assertEquals(Boolean.FALSE, result.getChecks().get("subjectIdMatches"), String.valueOf(result.getChecks()));
    }

    /** R-18. In Turtle there is no topmost map, so the graph must describe the subject at all. */
    @Test
    void selfSignedTurtleAboutSomebodyElseIsNotTheSubjectsDocument() throws Exception {
        SsiCidVerificationResult result = selfSigned("text/turtle",
                "<https://other.example/doc> <https://www.w3.org/ns/activitystreams#alsoKnownAs> <https://other.example/x> .")
                .result();
        assertEquals(Boolean.TRUE, result.getChecks().get("subjectDereferenced"));
        assertEquals(Boolean.FALSE, result.getChecks().get("subjectIdMatches"), String.valueOf(result.getChecks()));
    }

    /**
     * R-19. A context this provider does not bundle sends the document to the compact reader, which read
     * a {@code type} array as no type at all.
     */
    @Test
    void selfSignedTheCompactReaderReadsATypeArray() throws Exception {
        SsiCidVerificationResult result = selfSigned("application/ld+json", "{" + UNBUNDLED_CONTEXT
                + "\"id\":\"SUB\",\"authentication\":[" + MULTIKEY_METHOD.replace("\"Multikey\"", "[\"Multikey\"]")
                + "]}").result();
        assertTrue(result.isValid(), result.getErrors() + " " + result.getChecks());
    }

    // ---------------------------------------------------------------------------------- OpenID

    private VerificationResult openId(String contentType, String document) {
        String sub = serve(contentType, document.replace("ISS", issuer()));
        long now = Instant.now().getEpochSecond();
        String claims = "{\"sub\":\"" + sub + "\",\"iss\":\"" + issuer() + "\",\"azp\":\"https://client.example\","
                + "\"aud\":[\"https://client.example\"],\"iat\":" + now + ",\"exp\":" + (now + 300) + "}";
        String jwt = b64("{\"alg\":\"RS256\",\"typ\":\"JWT\"}") + "." + b64(claims) + "." + b64("unsigned");
        return new LWSCredentialVerifier(null).verify(jwt);
    }

    private String issuer() {
        return "http://localhost:" + port + "/op";
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static final String OP_SERVICE =
            "{\"id\":\"SUB#op\",\"type\":\"" + LWS_OPENID_PROVIDER + "\",\"serviceEndpoint\":\"ISS\"}";

    private static void assertProviderLocated(VerificationResult result) {
        assertEquals(Boolean.TRUE, result.getChecks().get("subjectIdMatches"), String.valueOf(result.getChecks()));
        assertEquals(Boolean.TRUE, result.getChecks().get("openIdProviderServiceLocated"),
                result.getErrors() + " " + result.getChecks());
    }

    @Test
    void openIdADocumentWithoutAContextDeclaresItsProvider() {
        for (String type : new String[]{"application/ld+json", "application/cid", "application/json"}) {
            assertProviderLocated(openId(type, "{\"id\":\"SUB\",\"service\":[" + OP_SERVICE + "]}"));
        }
    }

    /** R-18, as demonstrated in the review: the subject's node nested under another document's id. */
    @Test
    void openIdADocumentAboutSomebodyElseIsNotTheSubjectsDocument() {
        VerificationResult result = openId("application/ld+json", "{" + CID_CONTEXT
                + "\"id\":\"https://other.example/doc\",\"alsoKnownAs\":[{\"id\":\"SUB\",\"service\":["
                + OP_SERVICE + "]}]}");
        assertFalse(result.isValid());
        assertEquals(Boolean.TRUE, result.getChecks().get("subjectDereferenced"));
        assertEquals(Boolean.FALSE, result.getChecks().get("subjectIdMatches"), String.valueOf(result.getChecks()));
        assertEquals(null, result.getChecks().get("openIdProviderServiceLocated"), "not consulted");
    }

    /**
     * R-19. Through the compact reader, a {@code type} array used to read as "" and only the first
     * {@code serviceEndpoint} counted, so naming one unbundled context changed the verdict.
     */
    @Test
    void openIdTheCompactReaderReadsEveryTypeAndEndpoint() {
        String service = "{\"id\":\"SUB#op\",\"type\":[\"https://type.example/Other\",\"" + LWS_OPENID_PROVIDER
                + "\"],\"serviceEndpoint\":[\"https://elsewhere.example/\",\"ISS\"]}";
        assertProviderLocated(openId("application/ld+json", "{" + UNBUNDLED_CONTEXT + "\"id\":\"SUB\",\"service\":["
                + service + "]}"));
    }

    /** And the processor path agrees, as it always did. */
    @Test
    void openIdTheProcessorReadsEveryTypeAndEndpoint() {
        String service = "{\"id\":\"SUB#op\",\"type\":[\"https://type.example/Other\",\"" + LWS_OPENID_PROVIDER
                + "\"],\"serviceEndpoint\":[\"https://elsewhere.example/\",\"ISS\"]}";
        assertProviderLocated(openId("application/ld+json", "{" + CID_CONTEXT + "\"id\":\"SUB\",\"service\":["
                + service + "]}"));
    }
}
