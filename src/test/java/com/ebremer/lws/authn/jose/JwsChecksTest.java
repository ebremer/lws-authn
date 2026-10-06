/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.keycloak.jose.jws.JWSInput;

/**
 * The checks both JWT suites share. Getting these wrong once is getting them wrong twice, which is
 * why they live in one place.
 */
class JwsChecksTest {

    private static JWSInput jws(String headerJson) throws Exception {
        String encoded = b64(headerJson) + "." + b64("{\"sub\":\"x\"}") + "." + b64("sig");
        return new JWSInput(encoded);
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    // ------------------------------------------------------------------------------- crit (§4.1.11)

    /**
     * Keycloak's JWSHeader is annotated {@code @JsonIgnoreProperties(ignoreUnknown = true)}, so it
     * drops {@code crit} silently — the exact failure the header exists to prevent. These read the raw
     * encoded header instead.
     */
    @Test
    void findsCriticalHeaders() throws Exception {
        assertEquals(List.of("b64"), JwsChecks.criticalHeaders(jws("{\"alg\":\"ES256\",\"crit\":[\"b64\"]}")));
        assertEquals(List.of("b64", "x"),
                JwsChecks.criticalHeaders(jws("{\"alg\":\"ES256\",\"crit\":[\"b64\",\"x\"]}")));
    }

    @Test
    void reportsNothingWhenThereIsNoCrit() throws Exception {
        assertTrue(JwsChecks.criticalHeaders(jws("{\"alg\":\"ES256\",\"typ\":\"JWT\"}")).isEmpty());
        assertTrue(JwsChecks.criticalHeaders(jws("{\"alg\":\"ES256\",\"crit\":null}")).isEmpty());
    }

    /** RFC 7515 §4.1.11: the value MUST be a non-empty array. Malformed is not the same as absent. */
    @Test
    void treatsAMalformedCritAsPresent() throws Exception {
        assertFalse(JwsChecks.criticalHeaders(jws("{\"alg\":\"ES256\",\"crit\":[]}")).isEmpty());
        assertFalse(JwsChecks.criticalHeaders(jws("{\"alg\":\"ES256\",\"crit\":\"b64\"}")).isEmpty());
    }

    @Test
    void survivesAMissingJws() {
        assertTrue(JwsChecks.criticalHeaders(null).isEmpty());
    }

    /**
     * R-24. RFC 7515 §5.2: a header that does not decode means the JWS "MUST be rejected". This used to
     * report "no crit", while Keycloak's lenient decoder read the header up to the {@code =}.
     */
    @Test
    void anUndecodableHeaderCountsAsCritical() throws Exception {
        String header = b64("{\"alg\":\"ES256\",\"crit\":[\"urn:x\"]}") + "=junk";
        JWSInput jws = new JWSInput(header + "." + b64("{\"sub\":\"x\"}") + "." + b64("sig"));
        assertFalse(JwsChecks.criticalHeaders(jws).isEmpty());
    }

    // --------------------------------------------------------------- compact serialization (R-24)

    @Test
    void acceptsOnlyStrictBase64urlInThreeSegments() {
        String good = b64("{\"alg\":\"ES256\"}") + "." + b64("{\"sub\":\"x\"}") + "." + b64("signature");
        assertTrue(JwsChecks.compactSerializationWellFormed(good));
        for (String bad : new String[]{
                null, "", good + "=", good.replace(".", "=."), good + ".", "." + good,
                good.substring(0, good.lastIndexOf('.')),          // two segments
                good + "." + b64("x"),                             // four
                good.replace(".", ". "), good + "\n", " " + good,  // whitespace
                good.replace('-', '+').replace('_', '/') + "+/",   // base64, not base64url
                good + "A"}) {                                     // a length no encoding has
            assertFalse(JwsChecks.compactSerializationWellFormed(bad), String.valueOf(bad));
        }
    }

    // ------------------------------------------------------------------- NumericDate (R-24)

    @Test
    void datesMustBeJsonNumbers() throws Exception {
        assertTrue(JwsChecks.nonNumericDates(bytes("{\"exp\":1900000000,\"iat\":1800000000,\"nbf\":1800000000}")).isEmpty());
        assertTrue(JwsChecks.nonNumericDates(bytes("{\"exp\":1900000000.5}")).isEmpty(),
                "RFC 7519 §2: non-integer values can be represented");
        assertTrue(JwsChecks.nonNumericDates(bytes("{\"sub\":\"x\"}")).isEmpty(), "absence is checked elsewhere");
        assertEquals(List.of("exp"), JwsChecks.nonNumericDates(bytes("{\"exp\":\"1900000000\"}")));
        assertEquals(List.of("exp", "nbf", "iat"),
                JwsChecks.nonNumericDates(bytes("{\"exp\":null,\"nbf\":true,\"iat\":[1800000000]}")));
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    // --------------------------------------------------------------- signature length (R-24)

    /** RFC 7518 §3.4: an ES* signature is exactly 64, 96 or 132 octets; "If it is not … the validation has failed". */
    @Test
    void ecdsaSignaturesMustBeExactlyTheirLength() {
        assertTrue(JwsChecks.signatureLengthValid("ES256", new byte[64]));
        assertTrue(JwsChecks.signatureLengthValid("ES384", new byte[96]));
        assertTrue(JwsChecks.signatureLengthValid("ES512", new byte[132]));
        assertFalse(JwsChecks.signatureLengthValid("ES256", new byte[80]));
        assertFalse(JwsChecks.signatureLengthValid("ES256", new byte[63]));
        assertFalse(JwsChecks.signatureLengthValid("ES512", new byte[130]));
        assertFalse(JwsChecks.signatureLengthValid("ES256", null));
        assertTrue(JwsChecks.signatureLengthValid("RS256", new byte[7]), "left to the RSA provider, which checks");
    }

    // ------------------------------------------------------------------------- algorithm pinning

    @Test
    void pinsAlgorithmsToKeyTypes() throws Exception {
        PublicKey rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(new ECGenParameterSpec("secp256r1"));
        PublicKey ec = ecGen.generateKeyPair().getPublic();
        KeyPair ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

        assertTrue(JwsChecks.algMatchesKey("RS256", rsa));
        assertTrue(JwsChecks.algMatchesKey("PS512", rsa));
        assertTrue(JwsChecks.algMatchesKey("ES256", ec));
        assertTrue(JwsChecks.algMatchesKey("EdDSA", ed.getPublic()));

        assertFalse(JwsChecks.algMatchesKey("ES256", rsa), "an RSA key cannot produce an ECDSA signature");
        assertFalse(JwsChecks.algMatchesKey("RS256", ec));
    }

    /**
     * RFC 7518 §3.4: each ES* algorithm is one curve and one hash. A JCA verifier would accept a
     * SHA-512 signature from a P-256 key, which is valid ECDSA and not valid ES512.
     */
    @Test
    void pinsEcdsaAlgorithmsToTheirCurves() throws Exception {
        PublicKey p256 = ec("secp256r1");
        PublicKey p384 = ec("secp384r1");
        PublicKey p521 = ec("secp521r1");

        assertTrue(JwsChecks.algMatchesKey("ES256", p256));
        assertTrue(JwsChecks.algMatchesKey("ES384", p384));
        assertTrue(JwsChecks.algMatchesKey("ES512", p521));

        assertFalse(JwsChecks.algMatchesKey("ES512", p256), "ES512 is P-521, not P-256");
        assertFalse(JwsChecks.algMatchesKey("ES256", p384), "ES256 is P-256, not P-384");
        assertFalse(JwsChecks.algMatchesKey("ES384", p521), "ES384 is P-384, not P-521");
        assertFalse(JwsChecks.algMatchesKey("ES256K", p256), "secp256k1 is not a curve this provider supports");
    }

    private static PublicKey ec(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair().getPublic();
    }

    /** The attack this exists for: a public key must never be usable as an HMAC secret. */
    @Test
    void neverMatchesASymmetricOrAbsentAlgorithm() throws Exception {
        PublicKey rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
        assertFalse(JwsChecks.algMatchesKey("HS256", rsa));
        assertFalse(JwsChecks.algMatchesKey("none", rsa));
        assertFalse(JwsChecks.algMatchesKey("MADEUP", rsa));
        assertFalse(JwsChecks.algMatchesKey(null, rsa));
        assertFalse(JwsChecks.algMatchesKey("RS256", null));
    }

    // ---------------------------------------------------------------------------------- audience

    @Test
    void matchesAnAudienceExactly() {
        String[] audience = {"https://client.example", "https://as.example"};
        assertTrue(JwsChecks.audienceIncludes(audience, "https://as.example"));
        assertFalse(JwsChecks.audienceIncludes(audience, "https://as.example/"), "no normalisation is applied");
        assertFalse(JwsChecks.audienceIncludes(audience, "https://other.example"));
        assertFalse(JwsChecks.audienceIncludes(null, "https://as.example"));
        assertFalse(JwsChecks.audienceIncludes(audience, null));
        assertFalse(JwsChecks.audienceIncludes(new String[0], "https://as.example"));
    }

    /** RFC 8725 §3.11: absent or a JWT type is accepted; an access token's type is not (R-05). */
    @Test
    void acceptsOnlyAJwtTypeOrNone() {
        for (String typ : new String[]{null, "", "JWT", "jwt", "application/jwt", " JWT "}) {
            assertTrue(JwsChecks.typeIsJwtOrAbsent(typ), String.valueOf(typ));
        }
        for (String typ : new String[]{"at+jwt", "application/at+jwt", "AT+JWT", "logout+jwt", "dpop+jwt", "JWE"}) {
            assertFalse(JwsChecks.typeIsJwtOrAbsent(typ), typ);
        }
    }
}
