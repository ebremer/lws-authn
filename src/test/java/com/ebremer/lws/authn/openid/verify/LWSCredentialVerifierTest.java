/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.openid.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;

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

    /**
     * R-05. Keycloak writes {@code "typ": "JWT"} in the header of access tokens and ID Tokens alike; the
     * payload's own {@code typ} says which it is. With the WebID mapper on access tokens, a realm access
     * token carried everything else this verifier checks.
     */
    @Test
    void rejectsATokenWhosePayloadSaysItIsNotAnIdToken() {
        for (String type : new String[]{"Bearer", "DPoP", "Refresh", "Logout"}) {
            VerificationResult r = verify("{\"alg\":\"RS256\",\"typ\":\"JWT\"}",
                    "{\"typ\":\"" + type + "\",\"sub\":\"https://id.example/u\",\"iss\":\"https://op.example\","
                            + "\"azp\":\"https://c.example\"}");
            assertFalse(r.isValid(), type);
            assertEquals(Boolean.FALSE, r.getChecks().get("tokenIsIdToken"), type);
        }
    }

    /** An ID Token that says so, or says nothing — as most providers do — gets past the type check. */
    @Test
    void acceptsAnIdTokenTypeOrNone() {
        for (String claims : new String[]{
                "{\"typ\":\"ID\",\"sub\":\"https://id.example/u\",\"iss\":\"https://op.example\",\"azp\":\"https://c.example\"}",
                "{\"sub\":\"https://id.example/u\",\"iss\":\"https://op.example\",\"azp\":\"https://c.example\"}"}) {
            assertEquals(Boolean.TRUE, verify("{\"alg\":\"RS256\"}", claims).getChecks().get("tokenIsIdToken"), claims);
        }
    }

    /** R-05. {@code at+jwt} in the header is RFC 9068's explicit "this is an access token". */
    @Test
    void rejectsAHeaderTypedAsAnAccessToken() {
        VerificationResult r = verify("{\"alg\":\"RS256\",\"typ\":\"at+jwt\"}",
                "{\"sub\":\"https://id.example/u\",\"iss\":\"https://op.example\",\"azp\":\"https://c.example\"}");
        assertFalse(r.isValid());
        assertEquals(Boolean.FALSE, r.getChecks().get("typeIsJwt"));
    }

    /**
     * R-07. OpenID Connect Core §2: the Issuer Identifier is "a case-sensitive URL using the https scheme
     * that contains scheme, host, and optionally, port number and path components and no query or
     * fragment components". Its configuration and keys are fetched from it.
     */
    @Test
    void rejectsAnIssuerThatIsNotAnHttpsUrl() {
        for (String iss : new String[]{"http://op.example", "https://op.example?x=1", "https://op.example/#f",
                "https://user@op.example", "op.example", "urn:example:op", "https:///realms/r", "https://op .example"}) {
            VerificationResult r = verify("{\"alg\":\"RS256\"}",
                    "{\"sub\":\"https://id.example/u\",\"iss\":\"" + iss + "\",\"azp\":\"https://c.example\"}");
            assertFalse(r.isValid(), iss);
            assertEquals(Boolean.FALSE, r.getChecks().get("issuerWellFormed"), iss);
        }
    }

    /** A port and a path are fine; plain http only to a host the deployment has allow-listed. */
    @Test
    void anIssuerIdentifierMayHaveAPortAndAPath() {
        assertTrue(LWSCredentialVerifier.isIssuerIdentifier("https://op.example:8443/realms/r", Set.of()));
        assertTrue(LWSCredentialVerifier.isIssuerIdentifier("http://localhost:8080/realms/r", Set.of("localhost")));
        assertFalse(LWSCredentialVerifier.isIssuerIdentifier("http://localhost:8080/realms/r", Set.of()));
        assertEquals(Boolean.TRUE, verify("{\"alg\":\"RS256\"}",
                "{\"sub\":\"https://id.example/u\",\"iss\":\"https://op.example/realms/r\",\"azp\":\"https://c.example\"}")
                .getChecks().get("issuerWellFormed"));
    }

    private static final String CLAIMS = "\"sub\":\"https://id.example/u\",\"iss\":\"https://op.example\","
            + "\"azp\":\"https://c.example\"";

    /**
     * R-17. OpenID Connect Core §2: {@code iat} and {@code aud} are REQUIRED in an ID Token, whatever
     * the caller asks for. Both are checked before anything is fetched.
     */
    @Test
    void requiresIssuedAtAndAudience() {
        long now = java.time.Instant.now().getEpochSecond();
        VerificationResult noIat = verify("{\"alg\":\"RS256\"}",
                "{" + CLAIMS + ",\"aud\":[\"https://c.example\"],\"exp\":" + (now + 300) + "}");
        assertEquals(Boolean.FALSE, noIat.getChecks().get("issuedAtPresent"));
        assertFalse(noIat.isValid());

        for (String aud : new String[]{"", ",\"aud\":[]", ",\"aud\":[\"\"]", ",\"aud\":\"\"",
                ",\"aud\":[\"https://c.example\",\" \"]"}) {
            VerificationResult r = verify("{\"alg\":\"RS256\"}",
                    "{" + CLAIMS + aud + ",\"iat\":" + now + ",\"exp\":" + (now + 300) + "}");
            assertEquals(Boolean.FALSE, r.getChecks().get("audiencePresent"), aud);
            assertFalse(r.isValid(), aud);
        }
    }

    /** R-28, with R-17. An {@code iat} in the future, or after {@code exp}, is not one a clock wrote. */
    @Test
    void rejectsAnIssuedAtInTheFutureOrAfterExpiry() {
        long now = java.time.Instant.now().getEpochSecond();
        for (long[] times : new long[][]{{now + 86_400, now + 90_000}, {now + 50, now + 30}}) {
            VerificationResult r = verify("{\"alg\":\"RS256\"}", "{" + CLAIMS + ",\"aud\":[\"https://c.example\"],"
                    + "\"iat\":" + times[0] + ",\"exp\":" + times[1] + "}");
            assertEquals(Boolean.FALSE, r.getChecks().get("issuedAtConsistent"), java.util.Arrays.toString(times));
        }
        VerificationResult fine = verify("{\"alg\":\"RS256\"}", "{" + CLAIMS + ",\"aud\":[\"https://c.example\"],"
                + "\"iat\":" + now + ",\"exp\":" + (now + 300) + "}");
        assertEquals(Boolean.TRUE, fine.getChecks().get("issuedAtConsistent"));
        assertEquals(Boolean.TRUE, fine.getChecks().get("audiencePresent"));
    }

    /**
     * R-24. RFC 7515 §5.2: each part is base64url "with no line breaks, whitespace, or other additional
     * characters". A header with {@code =junk} appended read as one thing to Keycloak and another to the
     * {@code crit} check. Whitespace around the whole token is the form field's, and is ignored.
     */
    @Test
    void requiresAStrictCompactSerialization() {
        String token = token("{\"alg\":\"RS256\",\"crit\":[\"urn:x\"]}", "{" + CLAIMS + "}");
        String padded = token.replaceFirst("\\.", "=junk.");
        VerificationResult r = new LWSCredentialVerifier(null).verify(padded);
        assertFalse(r.isValid());
        assertEquals(Boolean.FALSE, r.getChecks().get("compactSerializationWellFormed"));

        VerificationResult trimmed = new LWSCredentialVerifier(null).verify("  " + token + "\n");
        assertEquals(Boolean.TRUE, trimmed.getChecks().get("compactSerializationWellFormed"));
        assertEquals(Boolean.FALSE, trimmed.getChecks().get("noUnsupportedCriticalHeaders"));
    }

    /** R-24. RFC 7519 §2: a NumericDate is a JSON number; Jackson read {@code "exp": "…"} as the same Long. */
    @Test
    void rejectsDatesThatAreNotNumbers() {
        long now = java.time.Instant.now().getEpochSecond();
        VerificationResult r = verify("{\"alg\":\"RS256\"}", "{" + CLAIMS + ",\"aud\":[\"https://c.example\"],"
                + "\"iat\":" + now + ",\"exp\":\"" + (now + 300) + "\"}");
        assertFalse(r.isValid());
        assertEquals(Boolean.FALSE, r.getChecks().get("numericDatesWellFormed"));
    }

    /** R-28. With a maximum lifetime configured, {@code exp − iat} over it is refused before any fetch. */
    @Test
    void aConfiguredMaximumLifetimeIsEnforced() {
        long now = java.time.Instant.now().getEpochSecond();
        String claims = "{" + CLAIMS + ",\"aud\":[\"https://c.example\"],\"iat\":" + now + ",\"exp\":" + (now + 86_400) + "}";
        assertEquals(null, verify("{\"alg\":\"RS256\"}", claims).getChecks().get("lifetimeWithinLimit"));
        System.setProperty("lws.authn.maxCredentialLifetimeSeconds", "3600");
        try {
            com.ebremer.lws.authn.config.ServerSettings.contribute("test", null);
            VerificationResult r = verify("{\"alg\":\"RS256\"}", claims);
            assertFalse(r.isValid());
            assertEquals(Boolean.FALSE, r.getChecks().get("lifetimeWithinLimit"));
        } finally {
            System.clearProperty("lws.authn.maxCredentialLifetimeSeconds");
            com.ebremer.lws.authn.config.ServerSettings.reset();
        }
    }
}
