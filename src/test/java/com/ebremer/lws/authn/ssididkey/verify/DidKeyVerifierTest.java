package com.ebremer.lws.authn.ssididkey.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import com.ebremer.lws.authn.ssididkey.DidKey;

/**
 * Unit tests for the self-signed {@code did:key} verifier. The verifier needs no session, network or
 * document, so it exercises the credential-validation rules directly.
 */
class DidKeyVerifierTest {

    @Test
    void validP256CredentialVerifies() throws Exception {
        KeyPair kp = ecP256();
        String did = DidKey.encodeP256((ECPublicKey) kp.getPublic());
        String jwt = sign(did, "ES256", claims(did, 300L, true), kp.getPrivate(), "SHA256withECDSAinP1363Format");

        DidKeyVerificationResult r = new SelfSignedDidKeyVerifier().verify(jwt);
        assertTrue(r.isValid(), () -> "expected valid, errors: " + r.getErrors());
        assertEquals("P-256", r.getKeyType());
    }

    /** Replay hardening: a credential with no {@code exp} must be rejected (would never expire). */
    @Test
    void missingExpRejected() throws Exception {
        KeyPair kp = ecP256();
        String did = DidKey.encodeP256((ECPublicKey) kp.getPublic());
        // correctly signed and aud-bearing, but no 'exp' claim
        String jwt = sign(did, "ES256", claimsNoExp(did), kp.getPrivate(), "SHA256withECDSAinP1363Format");

        DidKeyVerificationResult r = new SelfSignedDidKeyVerifier().verify(jwt);
        assertFalse(r.isValid(), "a credential without 'exp' must be rejected");
        assertEquals(Boolean.FALSE, r.getChecks().get("notExpired"));
    }

    /** Algorithm pinning: an Ed25519 did:key with a JWT header claiming ES256 must be rejected. */
    @Test
    void algNotMatchingKeyRejected() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String did = DidKey.encodeEd25519(kp.getPublic());
        // header says ES256 though the did:key embeds an Ed25519 key (EdDSA)
        String jwt = sign(did, "ES256", claims(did, 300L, true), kp.getPrivate(), "Ed25519");

        DidKeyVerificationResult r = new SelfSignedDidKeyVerifier().verify(jwt);
        assertFalse(r.isValid(), "alg/key-type mismatch must be rejected");
        assertEquals(Boolean.FALSE, r.getChecks().get("algorithmMatchesKey"));
    }

    // ------------------------------------------------------------------------------------ helpers

    private static KeyPair ecP256() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    private static String claims(String did, long expDeltaSeconds, boolean withAudience) {
        long now = System.currentTimeMillis() / 1000;
        String aud = withAudience ? ",\"aud\":[\"https://as.example\"]" : "";
        return "{\"sub\":\"" + did + "\",\"iss\":\"" + did + "\",\"client_id\":\"" + did + "\""
                + aud + ",\"iat\":" + now + ",\"exp\":" + (now + expDeltaSeconds) + "}";
    }

    private static String claimsNoExp(String did) {
        long now = System.currentTimeMillis() / 1000;
        return "{\"sub\":\"" + did + "\",\"iss\":\"" + did + "\",\"client_id\":\"" + did
                + "\",\"aud\":[\"https://as.example\"],\"iat\":" + now + "}";
    }

    private static String sign(String did, String alg, String payloadJson, PrivateKey key, String jdkAlg)
            throws Exception {
        String input = b64("{\"alg\":\"" + alg + "\",\"typ\":\"JWT\"}") + "." + b64(payloadJson);
        Signature s = Signature.getInstance(jdkAlg);
        s.initSign(key);
        s.update(input.getBytes(StandardCharsets.UTF_8));
        return input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(s.sign());
    }

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }
}
