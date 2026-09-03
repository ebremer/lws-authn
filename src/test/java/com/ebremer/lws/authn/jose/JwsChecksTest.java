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
 * The checks all three JWT suites share. Getting these wrong once is getting them wrong three times,
 * which is why they live in one place.
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
    void survivesAnUnreadableHeader() {
        // An unreadable header is the signature check's problem to report, not this one's.
        assertTrue(JwsChecks.criticalHeaders(null).isEmpty());
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
        assertTrue(JwsChecks.algMatchesKey("ES512", ec));
        assertTrue(JwsChecks.algMatchesKey("EdDSA", ed.getPublic()));

        assertFalse(JwsChecks.algMatchesKey("ES256", rsa), "an RSA key cannot produce an ECDSA signature");
        assertFalse(JwsChecks.algMatchesKey("RS256", ec));
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
}
