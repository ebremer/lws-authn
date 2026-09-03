package com.ebremer.lws.authn.ssididkey.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
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


    /** P1-D4: the did:key registry defines the other NIST curves too, and a peer may present one. */
    @Test
    void p384AndP521CredentialsVerify() throws Exception {
        for (String[] curve : new String[][]{{"secp384r1", "ES384", "P-384", "SHA384withECDSAinP1363Format"},
                                             {"secp521r1", "ES512", "P-521", "SHA512withECDSAinP1363Format"}}) {
            KeyPair kp = ec(curve[0]);
            String did = "P-384".equals(curve[2])
                    ? DidKey.encodeP384((ECPublicKey) kp.getPublic())
                    : DidKey.encodeP521((ECPublicKey) kp.getPublic());
            String jwt = sign(did, curve[1], claims(did, 300L, true), kp.getPrivate(), curve[3]);

            DidKeyVerificationResult r = new SelfSignedDidKeyVerifier().verify(jwt);
            assertTrue(r.isValid(), () -> "expected valid for " + curve[2] + ", errors: " + r.getErrors());
            assertEquals(curve[2], r.getKeyType());
        }
    }

    /** Ed25519 remains supported alongside them. */
    @Test
    void ed25519CredentialVerifies() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        String did = DidKey.encodeEd25519(kp.getPublic());
        String jwt = sign(did, "EdDSA", claims(did, 300L, true), kp.getPrivate(), "Ed25519");

        DidKeyVerificationResult r = new SelfSignedDidKeyVerifier().verify(jwt);
        assertTrue(r.isValid(), () -> "expected valid, errors: " + r.getErrors());
        assertEquals("Ed25519", r.getKeyType());
    }

    /**
     * P1-D5. A did:key *is* its key, so the mapping has to be one-to-one. base58 encodes leading zero
     * bytes as '1', and an extra one decodes to the same key bytes -- giving one agent two identifiers
     * unless the encoding is required to be canonical.
     */
    @Test
    void nonCanonicalEncodingRejected() throws Exception {
        KeyPair kp = ecP256();
        String did = DidKey.encodeP256((ECPublicKey) kp.getPublic());
        String padded = did.replace("did:key:z", "did:key:z1");

        assertThrows(IllegalArgumentException.class, () -> DidKey.decode(padded),
                "a non-canonical spelling of a key must not resolve to that key");

        String jwt = sign(padded, "ES256", claims(padded, 300L, true), kp.getPrivate(), "SHA256withECDSAinP1363Format");
        DidKeyVerificationResult r = new SelfSignedDidKeyVerifier().verify(jwt);
        assertFalse(r.isValid(), "a credential whose subject is a non-canonical did:key must be rejected");
    }

    /** Round-tripping every supported curve keeps encode and decode honest about each other. */
    @Test
    void everySupportedKeyTypeRoundTrips() throws Exception {
        KeyPair ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        assertEquals("Ed25519", DidKey.decode(DidKey.encodeEd25519(ed.getPublic())).keyType());
        assertEquals("P-256", DidKey.decode(DidKey.encodeP256((ECPublicKey) ecP256().getPublic())).keyType());
        assertEquals("P-384", DidKey.decode(DidKey.encodeP384((ECPublicKey) ec("secp384r1").getPublic())).keyType());
        assertEquals("P-521", DidKey.decode(DidKey.encodeP521((ECPublicKey) ec("secp521r1").getPublic())).keyType());
    }

    /** P1-D1: "The JWT MUST include an `iat` (issued at) claim." */
    @Test
    void missingIatRejected() throws Exception {
        KeyPair kp = ecP256();
        String did = DidKey.encodeP256((ECPublicKey) kp.getPublic());
        long now = System.currentTimeMillis() / 1000;
        String noIat = "{\"sub\":\"" + did + "\",\"iss\":\"" + did + "\",\"client_id\":\"" + did
                + "\",\"aud\":[\"https://as.example\"],\"exp\":" + (now + 300) + "}";
        String jwt = sign(did, "ES256", noIat, kp.getPrivate(), "SHA256withECDSAinP1363Format");

        DidKeyVerificationResult r = new SelfSignedDidKeyVerifier().verify(jwt);
        assertFalse(r.isValid(), "a credential without 'iat' must be rejected");
        assertEquals(Boolean.FALSE, r.getChecks().get("issuedAtPresent"));
    }

    /**
     * P1-D2: "The `aud` claim MUST include the target authorization server." Presence alone lets a
     * credential minted for one server be replayed at another.
     */
    @Test
    void audienceMustNameTheTargetAuthorizationServer() throws Exception {
        KeyPair kp = ecP256();
        String did = DidKey.encodeP256((ECPublicKey) kp.getPublic());
        String jwt = sign(did, "ES256", claims(did, 300L, true), kp.getPrivate(), "SHA256withECDSAinP1363Format");

        DidKeyVerificationResult matched = new SelfSignedDidKeyVerifier().verify(jwt, "https://as.example");
        assertTrue(matched.isValid(), () -> "errors: " + matched.getErrors());
        assertEquals(Boolean.TRUE, matched.getChecks().get("audienceMatched"));

        DidKeyVerificationResult other = new SelfSignedDidKeyVerifier().verify(jwt, "https://other-as.example");
        assertFalse(other.isValid(), "a credential not addressed to this server must be rejected");
        assertEquals(Boolean.FALSE, other.getChecks().get("audienceMatched"));
    }

    /** P1-D3 / RFC 7515 §5.2: critical headers we do not implement are fatal. */
    @Test
    void unsupportedCriticalHeaderRejected() throws Exception {
        KeyPair kp = ecP256();
        String did = DidKey.encodeP256((ECPublicKey) kp.getPublic());
        String header = "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"crit\":[\"exp\"]}";
        String input = b64(header) + "." + b64(claims(did, 300L, true));
        Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(kp.getPrivate());
        signer.update(input.getBytes(StandardCharsets.UTF_8));
        String jwt = input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());

        DidKeyVerificationResult r = new SelfSignedDidKeyVerifier().verify(jwt);
        assertFalse(r.isValid(), "a JWS with unsupported critical headers must be rejected");
        assertEquals(Boolean.FALSE, r.getChecks().get("noUnsupportedCriticalHeaders"));
    }

    /** P1-K1/K2: a result names the LWS client and the suite's token type. */
    @Test
    void reportsClientAndTokenType() throws Exception {
        KeyPair kp = ecP256();
        String did = DidKey.encodeP256((ECPublicKey) kp.getPublic());
        String jwt = sign(did, "ES256", claims(did, 300L, true), kp.getPrivate(), "SHA256withECDSAinP1363Format");

        DidKeyVerificationResult r = new SelfSignedDidKeyVerifier().verify(jwt);
        assertEquals(did, r.getClient());
        assertEquals("urn:ietf:params:oauth:token-type:jwt", r.getTokenType());
    }

    // ------------------------------------------------------------------------------------ helpers

    private static KeyPair ecP256() throws Exception {
        return ec("secp256r1");
    }

    private static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec(curve));
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
