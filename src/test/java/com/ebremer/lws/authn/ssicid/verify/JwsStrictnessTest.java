/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.ssicid.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;

import com.ebremer.lws.authn.did.DidKey;
import com.ebremer.lws.authn.testsupport.SelfIssuedJwts;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * R-24: RFC 7515 §5.2, RFC 7518 §3.4 and RFC 7519 §2, end to end through the self-signed CID verifier
 * with a {@code did:key} subject, so no network is needed. Each credential here is signed by the
 * subject's own key: these are things only the signer can do, which is why they are conformance gaps
 * rather than forgeries — but a verifier that two decoders read differently is not verifying one thing.
 */
class JwsStrictnessTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private static SsiCidVerificationResult verify(String jwt) {
        return new SelfSignedCidVerifier(null).verify(jwt, SelfIssuedJwts.AUDIENCE);
    }

    private static String methodId(String did) {
        return did + "#" + DidKey.multibaseValue(did);
    }

    /** Signs exactly the encoded header and payload given, however they are spelled. */
    private static String signEncoded(String encodedHeader, String encodedPayload, PrivateKey key, String jca)
            throws Exception {
        String input = encodedHeader + "." + encodedPayload;
        Signature signature = Signature.getInstance(jca);
        signature.initSign(key);
        signature.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + B64.encodeToString(signature.sign());
    }

    private static String header(String alg, String kid, Map<String, Object> extra) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg);
        header.put("typ", "JWT");
        header.put("kid", kid);
        header.putAll(extra);
        return B64.encodeToString(JSON.writeValueAsBytes(header));
    }

    /**
     * A signed header carrying {@code crit}, with {@code =junk} after its base64url. The strict decoder
     * could not read it and reported "no crit"; Keycloak's lenient one stopped at {@code =} and read the
     * header, so the credential verified with an extension nobody understood.
     */
    @Test
    void aCriticalHeaderBehindPaddingIsRejected() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());
        String jwt = signEncoded(header("EdDSA", methodId(did), Map.of("crit", List.of("urn:x"), "urn:x", true))
                + "=junk", B64.encodeToString(JSON.writeValueAsBytes(SelfIssuedJwts.claims(did))),
                pair.getPrivate(), "Ed25519");

        SsiCidVerificationResult result = verify(jwt);

        assertFalse(result.isValid(), "a header two decoders read differently must not verify");
        assertEquals(Boolean.FALSE, result.getChecks().get("compactSerializationWellFormed"));
    }

    /** RFC 7519 §2: a NumericDate is "a JSON numeric value". A string read as the same Long. */
    @Test
    void aDateWrittenAsAStringIsRejected() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());
        for (String claim : new String[]{"exp", "iat"}) {
            Map<String, Object> claims = SelfIssuedJwts.claims(did);
            claims.put(claim, String.valueOf(claims.get(claim)));
            String jwt = SelfIssuedJwts.sign(claims, "EdDSA", methodId(did), pair.getPrivate(), "Ed25519");

            SsiCidVerificationResult result = verify(jwt);

            assertFalse(result.isValid(), claim);
            assertEquals(Boolean.FALSE, result.getChecks().get("numericDatesWellFormed"), claim);
        }
    }

    /** RFC 7519 §2 also says "non-integer values can be represented": a fractional date is a number. */
    @Test
    void aFractionalDateIsStillANumber() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());
        Map<String, Object> claims = SelfIssuedJwts.claims(did);
        claims.put("exp", ((Long) claims.get("exp")) + 0.5);
        String jwt = SelfIssuedJwts.sign(claims, "EdDSA", methodId(did), pair.getPrivate(), "Ed25519");

        SsiCidVerificationResult result = verify(jwt);

        assertTrue(result.isValid(), () -> String.valueOf(result.getErrors()));
        assertEquals(Boolean.TRUE, result.getChecks().get("numericDatesWellFormed"));
    }

    /**
     * RFC 7518 §3.4: an ES256 signature "MUST be a 64-octet sequence". Keycloak's ECDSA verifier converts
     * R‖S to DER from the first 64 bytes and ignores the rest, so a valid signature with bytes appended
     * verified inside Keycloak. The session here hands out a verifier that does the same.
     */
    @Test
    void anOverlongEcdsaSignatureIsRejectedInsideKeycloak() throws Exception {
        KeyPair pair = SelfIssuedJwts.ec("secp256r1");
        String did = DidKey.encodeP256((ECPublicKey) pair.getPublic());
        String jwt = SelfIssuedJwts.sign(SelfIssuedJwts.claims(did), "ES256", methodId(did), pair.getPrivate(),
                "SHA256withECDSAinP1363Format");
        String overlong = jwt + "AAAAAAAAAAAAAAAAAAAAAA"; // 81 bytes: the 64 that verify, then zeros

        SsiCidVerificationResult control = new SelfSignedCidVerifier(keycloakLikeSession())
                .verify(jwt, SelfIssuedJwts.AUDIENCE);
        assertTrue(control.isValid(), () -> "the stand-in verifier must accept the genuine signature: "
                + control.getErrors());

        SsiCidVerificationResult result = new SelfSignedCidVerifier(keycloakLikeSession())
                .verify(overlong, SelfIssuedJwts.AUDIENCE);
        assertFalse(result.isValid(), "an 81-byte ES256 signature is not an ES256 signature");
        assertEquals(Boolean.FALSE, result.getChecks().get("signatureValid"));
    }

    /**
     * A session whose ES256 {@code SignatureProvider} reads a signature the way Keycloak's does: the first
     * 64 bytes as R‖S, whatever follows them. Everything else a session offers is unsupported — a
     * {@code did:key} needs no fetch.
     */
    private static KeycloakSession keycloakLikeSession() {
        Object provider = Proxy.newProxyInstance(JwsStrictnessTest.class.getClassLoader(),
                new Class<?>[]{org.keycloak.crypto.SignatureProvider.class}, (proxy, method, args) -> {
                    if ("verifier".equals(method.getName()) && args != null && args[0] instanceof KeyWrapper key) {
                        return firstSixtyFourBytes((PublicKey) key.getPublicKey());
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        return (KeycloakSession) Proxy.newProxyInstance(JwsStrictnessTest.class.getClassLoader(),
                new Class<?>[]{KeycloakSession.class}, (proxy, method, args) -> {
                    if ("getProvider".equals(method.getName()) && args != null && args.length == 2) {
                        return provider;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static SignatureVerifierContext firstSixtyFourBytes(PublicKey key) {
        return new SignatureVerifierContext() {
            @Override
            public String getKid() {
                return null;
            }

            @Override
            public String getAlgorithm() {
                return "ES256";
            }

            @Override
            public boolean verify(byte[] data, byte[] signature) {
                try {
                    Signature verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
                    verifier.initVerify(key);
                    verifier.update(data);
                    return verifier.verify(Arrays.copyOf(signature, 64));
                } catch (Exception e) {
                    return false;
                }
            }
        };
    }
}
