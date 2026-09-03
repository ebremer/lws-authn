package com.ebremer.lws.authn.openid.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * The OpenID verifier's claim-level rules, exercised for the ones that are decided before anything is
 * dereferenced — so no Keycloak session and no network are needed. The rest of the algorithm
 * (dereference, discovery, JWKS, signature) still needs the container integration test, or the local
 * HTTP stub that TODO.md P5-1 calls for.
 */
class LWSCredentialVerifierTest {

    /** A syntactically valid JWS with a junk signature: enough to reach the claim checks. */
    private static String token(String headerJson, String claimsJson) {
        return b64(headerJson) + "." + b64(claimsJson) + "." + b64("not-a-real-signature");
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    private static VerificationResult verify(String header, String claims) {
        // The session is only touched once dereferencing starts, which none of these reach.
        return new LWSCredentialVerifier(null).verify(token(header, claims));
    }

    @Test
    void rejectsTheNoneAlgorithm() {
        VerificationResult r = verify("{\"alg\":\"none\"}",
                "{\"sub\":\"https://id.example/u\",\"iss\":\"https://op.example\",\"azp\":\"https://c.example\"}");
        assertFalse(r.isValid());
        assertEquals(Boolean.FALSE, r.getChecks().get("signingAlgorithmNotNone"));
    }

    /** P1-O4 / RFC 7515 §5.2: a critical header this provider does not implement is fatal. */
    @Test
    void rejectsUnsupportedCriticalHeaders() {
        VerificationResult r = verify("{\"alg\":\"RS256\",\"crit\":[\"b64\"]}",
                "{\"sub\":\"https://id.example/u\",\"iss\":\"https://op.example\",\"azp\":\"https://c.example\"}");
        assertFalse(r.isValid());
        assertEquals(Boolean.FALSE, r.getChecks().get("noUnsupportedCriticalHeaders"));
    }

    /**
     * P1-O1. The suite: "The ID Token MUST use the `azp` (authorized party) claim for the LWS client
     * identifier", and LWS core §4.1 makes the client a REQUIRED claim. It was previously not read at
     * all.
     */
    @Test
    void requiresTheAuthorizedPartyClaim() {
        VerificationResult r = verify("{\"alg\":\"RS256\"}",
                "{\"sub\":\"https://id.example/u\",\"iss\":\"https://op.example\"}");
        assertFalse(r.isValid());
        assertEquals(Boolean.FALSE, r.getChecks().get("clientPresent"));
    }

    @Test
    void reportsTheClientAndTokenType() {
        VerificationResult r = verify("{\"alg\":\"RS256\"}",
                "{\"sub\":\"https://id.example/u\",\"iss\":\"https://op.example\",\"azp\":\"https://c.example\"}");
        // It still fails -- there is nothing to dereference -- but the identifiers are already reported.
        assertEquals("https://c.example", r.getClient());
        assertEquals("urn:ietf:params:oauth:token-type:id_token", r.getTokenType());
        assertEquals(Boolean.TRUE, r.getChecks().get("clientPresent"));
    }

    @Test
    void requiresSubjectAndIssuer() {
        VerificationResult noSub = verify("{\"alg\":\"RS256\"}", "{\"iss\":\"https://op.example\"}");
        assertEquals(Boolean.FALSE, noSub.getChecks().get("subjectPresent"));

        VerificationResult noIss = verify("{\"alg\":\"RS256\"}", "{\"sub\":\"https://id.example/u\"}");
        assertEquals(Boolean.FALSE, noIss.getChecks().get("issuerPresent"));
    }

    /** P0-4: every rejection is traceable to a log line without describing the server in the response. */
    @Test
    void everyRejectionCarriesATraceId() {
        assertNotNull(verify("{\"alg\":\"none\"}", "{}").getTraceId());
        assertNotNull(new LWSCredentialVerifier(null).verify("not a jwt at all").getTraceId());
    }
}
