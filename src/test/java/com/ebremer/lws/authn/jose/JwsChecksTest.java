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
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.JsonWebToken;

import com.ebremer.lws.authn.config.ServerSettings;

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

    // -------------------------------------------------------------- key strength and use (R-27)

    /** RFC 7518 §3.3: "A key of size 2048 bits or larger MUST be used with these algorithms." */
    @Test
    void rsaKeysUnder2048BitsAreTooWeak() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(1024);
        assertFalse(JwsChecks.keyStrongEnough(g.generateKeyPair().getPublic()));
        g.initialize(2048);
        assertTrue(JwsChecks.keyStrongEnough(g.generateKeyPair().getPublic()));
        assertTrue(JwsChecks.keyStrongEnough(ec("secp256r1")), "an EC key's strength is its curve, pinned elsewhere");
    }

    @Test
    void keyOpsMustIncludeVerifyWhenPresent() throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper json = new com.fasterxml.jackson.databind.ObjectMapper();
        assertTrue(JwsChecks.keyOpsAllowVerify(json.readTree("{\"kty\":\"EC\"}")));
        assertTrue(JwsChecks.keyOpsAllowVerify(json.readTree("{\"key_ops\":[\"verify\",\"sign\"]}")));
        assertFalse(JwsChecks.keyOpsAllowVerify(json.readTree("{\"key_ops\":[\"encrypt\"]}")));
        assertFalse(JwsChecks.keyOpsAllowVerify(json.readTree("{\"key_ops\":\"verify\"}")), "RFC 7517: an array");
    }

    /** An OKP JWK gets the same Ed25519 point checks a did:key does. */
    @Test
    void anEd25519JwkMustNotBeASmallOrderPoint() throws Exception {
        com.fasterxml.jackson.databind.ObjectMapper json = new com.fasterxml.jackson.databind.ObjectMapper();
        byte[] identity = new byte[32];
        identity[0] = 1;
        String x = Base64.getUrlEncoder().withoutPadding().encodeToString(identity);
        assertTrue(JwsChecks.edwardsKeyProblem(json.readTree("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + x + "\"}"))
                .contains("small order"));
        byte[] spki = KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic().getEncoded();
        String real = Base64.getUrlEncoder().withoutPadding().encodeToString(
                java.util.Arrays.copyOfRange(spki, spki.length - 32, spki.length));
        assertEquals(null, JwsChecks.edwardsKeyProblem(json.readTree("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + real + "\"}")));
        assertEquals(null, JwsChecks.edwardsKeyProblem(json.readTree("{\"kty\":\"EC\"}")), "not an Ed25519 key");
    }

    // ---------------------------------------------------------------------------------- R-38

    private static String b64u(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** {@code value} as Ed448's 57-byte little-endian encoding, with the sign bit {@code xOdd}. */
    private static byte[] ed448(java.math.BigInteger value, boolean xOdd) {
        byte[] out = new byte[57];
        byte[] big = value.toByteArray();
        for (int i = 0; i < big.length && i < 57; i++) {
            out[i] = big[big.length - 1 - i];
        }
        if (xOdd) {
            out[56] |= (byte) 0x80;
        }
        return out;
    }

    private static String ed448Problem(byte[] x) throws Exception {
        return JwsChecks.edwardsKeyProblem(new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree("{\"kty\":\"OKP\",\"crv\":\"Ed448\",\"x\":\"" + b64u(x) + "\"}"));
    }

    /**
     * R-38. Keycloak verifies Ed448 too, and the JDK accepts the same forgery on it that R-27 found on
     * Ed25519: with the identity point as the key, {@code (R = identity, S = 0)} verifies any message. So
     * every point of small order — the identity, {@code (0, −1)} and {@code (±1, 0)} — is refused, and so
     * are non-canonical encodings and points off the curve.
     */
    @Test
    void anEd448JwkMustBeACanonicalPointOfLargeOrder() throws Exception {
        java.math.BigInteger p = java.math.BigInteger.TWO.pow(448).subtract(java.math.BigInteger.TWO.pow(224))
                .subtract(java.math.BigInteger.ONE);

        // The forgery, against the JDK's own verifier.
        java.security.PublicKey identity = java.security.KeyFactory.getInstance("EdDSA").generatePublic(
                new java.security.spec.EdECPublicKeySpec(java.security.spec.NamedParameterSpec.ED448,
                        new java.security.spec.EdECPoint(false, java.math.BigInteger.ONE)));
        java.security.Signature jdk = java.security.Signature.getInstance("Ed448");
        jdk.initVerify(identity);
        jdk.update("anything at all".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        byte[] forged = new byte[114];
        forged[0] = 1;
        assertTrue(jdk.verify(forged), "the JDK accepts it, which is why the key is checked first");

        assertTrue(ed448Problem(ed448(java.math.BigInteger.ONE, false)).contains("small order"), "identity");
        assertTrue(ed448Problem(ed448(p.subtract(java.math.BigInteger.ONE), false)).contains("small order"), "(0, -1)");
        assertTrue(ed448Problem(ed448(java.math.BigInteger.ZERO, false)).contains("small order"), "(-1, 0)");
        assertTrue(ed448Problem(ed448(java.math.BigInteger.ZERO, true)).contains("small order"), "(1, 0)");
        assertTrue(ed448Problem(ed448(p.add(java.math.BigInteger.ONE), false)).contains("not canonically encoded"));
        assertTrue(ed448Problem(ed448(java.math.BigInteger.ONE, true)).contains("not canonically encoded"),
                "x = 0 with the sign bit set");
        assertTrue(ed448Problem(new byte[32]).contains("57 bytes"));
        boolean offTheCurve = false;
        for (int y = 2; y < 40 && !offTheCurve; y++) {
            String problem = ed448Problem(ed448(java.math.BigInteger.valueOf(y), false));
            offTheCurve = problem != null && problem.contains("not a point on the curve");
        }
        assertTrue(offTheCurve, "about half of all y have no x");

        for (int i = 0; i < 20; i++) {
            byte[] spki = KeyPairGenerator.getInstance("Ed448").generateKeyPair().getPublic().getEncoded();
            assertEquals(null, ed448Problem(java.util.Arrays.copyOfRange(spki, spki.length - 57, spki.length)));
        }
    }

    /** R-38. The JDK path verifies EdDSA on whichever curve the key is, as Keycloak's does. */
    @Test
    void edDsaVerifiesOnTheKeysCurve() throws Exception {
        for (String curve : new String[]{"Ed25519", "Ed448"}) {
            java.security.KeyPair pair = KeyPairGenerator.getInstance(curve).generateKeyPair();
            String input = b64u("{\"alg\":\"EdDSA\"}".getBytes()) + "." + b64u("{}".getBytes());
            java.security.Signature signer = java.security.Signature.getInstance(curve);
            signer.initSign(pair.getPrivate());
            signer.update(input.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            org.keycloak.jose.jws.JWSInput jws = new org.keycloak.jose.jws.JWSInput(input + "." + b64u(signer.sign()));
            assertTrue(JwsSignatures.verify("EdDSA", pair.getPublic(), jws), curve);
        }
    }

    // ----------------------------------------------------------------- the validity window (R-44)

    private static JsonWebToken token(Long exp, Long nbf) {
        JsonWebToken token = new JsonWebToken();
        token.exp(exp);
        token.nbf(nbf);
        return token;
    }

    private static long now() {
        return Instant.now().getEpochSecond();
    }

    /**
     * R-44. Both JWT suites refuse an expired credential, allowing the configured skew and no more: from
     * {@code exp + skew} on it is refused, at the boundary included. A missing or zero {@code exp} is
     * refused too, where Keycloak's own {@code isActive()} would read it as "never expires".
     */
    @Test
    void expiryIsEnforcedToTheSkewAndNoFurther() {
        long skew = JwsChecks.clockSkewSeconds();
        long now = now();
        assertTrue(JwsChecks.withinValidityWindow(token(now + 300, null)));
        assertTrue(JwsChecks.withinValidityWindow(token(now - skew + 5, null)), "expired, but within the skew");
        assertFalse(JwsChecks.withinValidityWindow(token(now - skew, null)), "expired by exactly the skew");
        assertFalse(JwsChecks.withinValidityWindow(token(now - 3600, null)));
        assertFalse(JwsChecks.withinValidityWindow(token(null, null)), "no exp is not 'never expires'");
        assertFalse(JwsChecks.withinValidityWindow(token(0L, null)), "nor is an exp of 0");
        assertFalse(JwsChecks.withinValidityWindow(null));
    }

    /**
     * R-44. A credential is not valid before its {@code nbf}, allowing the skew: from {@code nbf − skew}
     * on it is, the boundary included. An absent or zero {@code nbf} imposes nothing.
     */
    @Test
    void notBeforeIsEnforcedToTheSkewAndNoFurther() {
        long skew = JwsChecks.clockSkewSeconds();
        long now = now();
        long exp = now + 3600;
        assertTrue(JwsChecks.withinValidityWindow(token(exp, now - 10)));
        assertTrue(JwsChecks.withinValidityWindow(token(exp, now + skew)), "not yet valid, but by exactly the skew");
        assertFalse(JwsChecks.withinValidityWindow(token(exp, now + skew + 5)), "not yet valid, beyond the skew");
        assertTrue(JwsChecks.withinValidityWindow(token(exp, null)));
        assertTrue(JwsChecks.withinValidityWindow(token(exp, 0L)));
    }

    /**
     * R-44. The skew is the configured {@code clock-skew-seconds}, not a constant: at {@code 0}, a
     * credential is refused from the second it expires and until the second it becomes valid.
     */
    @Test
    void theSkewIsTheConfiguredOne() {
        System.setProperty("lws.authn.clockSkewSeconds", "0");
        try {
            ServerSettings.contribute("test", null);
            assertEquals(0, JwsChecks.clockSkewSeconds());
            long now = now();
            assertFalse(JwsChecks.withinValidityWindow(token(now, null)));
            assertTrue(JwsChecks.withinValidityWindow(token(now + 5, null)));
            assertFalse(JwsChecks.withinValidityWindow(token(now + 3600, now + 5)));
        } finally {
            System.clearProperty("lws.authn.clockSkewSeconds");
            ServerSettings.reset();
        }
    }
}
