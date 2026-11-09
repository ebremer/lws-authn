/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.ssicid.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;

import com.ebremer.lws.authn.net.OutboundHttp;
import com.ebremer.lws.authn.rdf.RdfParsing;
import com.ebremer.lws.authn.ssicid.SsiCidConstants;

/**
 * The self-signed CID suite's own examples, as published in the Working Draft of 15 October 2026
 * (https://www.w3.org/TR/2026/WD-lws10-authn-ssi-cid-20261015/, Examples 1 and 2; unchanged in the
 * editor's draft of 9 November 2026), run through the verifier.
 *
 * <p>Both are used exactly as printed, whitespace and member order included: Example 1's header and
 * payload are the JWS's own bytes, and Example 2 is the document the subject's server answers with. The
 * one change is the payload's {@code iat} and {@code exp}, moved from October 2025 to now with the
 * example's five minutes between them; {@link #theExampleAsPrintedFailsOnlyForItsDates} shows that its
 * dates are all that stands between the example and a valid credential.</p>
 *
 * <p>The example can be signed because its key is a published one: {@code x} and {@code y} are those
 * of the P-256 key in RFC 7515 Appendix A.3, whose private {@code d} is printed there too. So the
 * document is the subject's real document for a key this test holds, not a stand-in.</p>
 *
 * <p>Keycloak initializes its {@code CryptoIntegration} at boot, and building a {@code JsonWebKey}'s EC
 * key goes through it; outside Keycloak it has to be initialized first, as it is here.</p>
 */
class SelfSignedCidSpecificationExampleTest {

    @BeforeAll
    static void initializeCrypto() {
        CryptoIntegration.init(SelfSignedCidSpecificationExampleTest.class.getClassLoader());
    }

    private static final String SUBJECT = "https://id.example/agent";
    private static final String AUTHORIZATION_SERVER = "https://as.example";

    /** Example 1's JOSE header, as printed. */
    private static final String HEADER = """
            {
              "kid": "c1f52577",
              "kty": "EC",
              "alg": "ES256",
              "typ": "JWT",
              "crv": "P-256"
            }""";

    /** Example 1's payload, as printed: {@code IAT} and {@code EXP} stand for its two dates. */
    private static final String PAYLOAD = """
            {
              "sub": "https://id.example/agent",
              "iss": "https://id.example/agent",
              "client_id": "https://id.example/agent",
              "aud": ["https://as.example"],
              "iat": IAT,
              "exp": EXP
            }""";

    /** Example 1's own dates: 24 October 2025, 13:46:40 and five minutes later. */
    private static final long EXAMPLE_IAT = 1761313600L;
    private static final long EXAMPLE_EXP = 1761313900L;

    /** Example 2, the subject's controlled identifier document, as printed. */
    private static final String DOCUMENT = """
            {
                "@context": [
                    "https://www.w3.org/ns/cid/v1" ],
                "id": "https://id.example/agent",
                "authentication": [{
                    "id": "https://id.example/agent#c1f52577",
                    "type": "JsonWebKey",
                    "controller": "https://id.example/agent",
                    "publicKeyJwk": {
                        "kid": "c1f52577",
                        "kty": "EC",
                        "crv": "P-256",
                        "alg": "ES256",
                        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
                    }
                }]
            }""";

    /** RFC 7515 Appendix A.3: the private key whose public half Example 2 publishes. */
    private static final String RFC_7515_A3_D = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";

    /** The subject's server, answering every request with {@link #DOCUMENT}, and the requests it saw. */
    private static final class SubjectServer implements SelfSignedCidVerifier.Fetcher {
        private final String contentType;
        final List<String> requested = new ArrayList<>();

        SubjectServer(String contentType) {
            this.contentType = contentType;
        }

        @Override
        public OutboundHttp.Fetched fetch(String url, String accept, boolean followRedirects) {
            requested.add(url);
            return new OutboundHttp.Fetched(200, contentType, DOCUMENT);
        }
    }

    private static PrivateKey rfc7515A3Key() throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        BigInteger d = new BigInteger(1, Base64.getUrlDecoder().decode(RFC_7515_A3_D));
        return KeyFactory.getInstance("EC").generatePrivate(
                new ECPrivateKeySpec(d, parameters.getParameterSpec(ECParameterSpec.class)));
    }

    /** Example 1 with these dates, signed with the example's key: ES256, R‖S as RFC 7518 §3.4 has it. */
    private static String example(long iat, long exp) throws Exception {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String payload = PAYLOAD.replace("IAT", Long.toString(iat)).replace("EXP", Long.toString(exp));
        String input = b64.encodeToString(HEADER.getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        Signature signature = Signature.getInstance("SHA256withECDSAinP1363Format");
        signature.initSign(rfc7515A3Key());
        signature.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + b64.encodeToString(signature.sign());
    }

    private static String currentExample() throws Exception {
        long now = Instant.now().getEpochSecond();
        return example(now, now + (EXAMPLE_EXP - EXAMPLE_IAT));
    }

    private static Map<String, Boolean> failed(SsiCidVerificationResult result) {
        Map<String, Boolean> failed = new java.util.LinkedHashMap<>(result.getChecks());
        failed.values().removeIf(Boolean.TRUE::equals);
        return failed;
    }

    /**
     * Example 1, signed, verifies against Example 2 for the authorization server it names — served as
     * JSON-LD and as CID 1.0's own media type — and the result reports the suite's subject, client and
     * token type identifier. The key is found by the {@code kid} as the suite says (CID 1.0 §3.3: here
     * the fragment of the method's {@code id}), and the subject's document is the one thing fetched.
     */
    @Test
    void theExampleCredentialVerifiesAgainstTheExampleDocument() throws Exception {
        for (String contentType : new String[]{"application/ld+json", RdfParsing.CID}) {
            SubjectServer server = new SubjectServer(contentType);
            SsiCidVerificationResult result = new SelfSignedCidVerifier(null).fetchingWith(server)
                    .verify(currentExample(), AUTHORIZATION_SERVER);

            assertTrue(result.isValid(), () -> contentType + ": " + result.getErrors() + " " + result.getChecks());
            assertTrue(failed(result).isEmpty(), () -> contentType + ": " + result.getChecks());
            assertEquals(SUBJECT, result.getSubject());
            assertEquals(SUBJECT, result.getClient());
            assertEquals(SsiCidConstants.TOKEN_TYPE_JWT, result.getTokenType());
            for (String check : new String[]{"selfIssued", "keyIdPresent", "subjectIdMatches", "verificationMethodFound",
                    "verificationMethodActive", "algorithmMatchesKey", "signatureValid", "notExpired",
                    "issuedAtPresent", "audiencePresent", "audienceMatched"}) {
                assertEquals(Boolean.TRUE, result.getChecks().get(check), contentType + ": " + check);
            }
            assertEquals(List.of(SUBJECT), server.requested, contentType);
        }
    }

    /**
     * Example 1 with its own dates is a well-formed, correctly signed credential that expired in October
     * 2025: {@code notExpired} is the one check that fails, so moving the dates is the only liberty the
     * other tests take with it.
     */
    @Test
    void theExampleAsPrintedFailsOnlyForItsDates() throws Exception {
        SsiCidVerificationResult result = new SelfSignedCidVerifier(null)
                .fetchingWith(new SubjectServer("application/ld+json"))
                .verify(example(EXAMPLE_IAT, EXAMPLE_EXP), AUTHORIZATION_SERVER);

        assertFalse(result.isValid());
        assertEquals(Map.of("notExpired", false), failed(result), () -> result.getErrors().toString());
        assertEquals(Boolean.TRUE, result.getChecks().get("signatureValid"));
    }

    /**
     * "The {@code aud} claim MUST include the target authorization server": the example credential names
     * {@code https://as.example}, so to any other authorization server it is not valid.
     */
    @Test
    void theExampleCredentialIsNotValidForAnotherAuthorizationServer() throws Exception {
        SsiCidVerificationResult result = new SelfSignedCidVerifier(null)
                .fetchingWith(new SubjectServer("application/ld+json"))
                .verify(currentExample(), "https://other-as.example");

        assertFalse(result.isValid());
        assertEquals(Map.of("audienceMatched", false), failed(result), () -> result.getErrors().toString());
    }
}
