/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.testsupport;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Mints self-issued JWTs the way an LWS agent would, signed with the JDK in the JOSE signature format,
 * so the self-signed suites can be exercised end to end without a Keycloak runtime.
 */
public final class SelfIssuedJwts {

    private SelfIssuedJwts() {
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    /** The audience every minted credential names unless a test says otherwise. */
    public static final String AUDIENCE = "https://as.example";

    public static KeyPair ed25519() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    /** An EC key pair on a JDK-named curve: secp256r1, secp384r1 or secp521r1. */
    public static KeyPair ec(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    /** An RSA key pair of {@code bits} bits. */
    public static KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return generator.generateKeyPair();
    }

    /** Claims for a credential whose {@code sub == iss == client_id == subject}, valid for five minutes. */
    public static Map<String, Object> claims(String subject) {
        long now = Instant.now().getEpochSecond();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", subject);
        claims.put("iss", subject);
        claims.put("client_id", subject);
        claims.put("aud", List.of(AUDIENCE));
        claims.put("iat", now);
        claims.put("exp", now + 300);
        return claims;
    }

    /**
     * Signs {@code claims} as a compact JWS.
     *
     * @param alg the JOSE algorithm written into the header
     * @param kid the key id written into the header, or {@code null} for none
     * @param key the private key to sign with
     * @param jca the JCA signature algorithm actually used — normally the one {@code alg} names, but a
     *            test may make them disagree on purpose
     */
    public static String sign(Map<String, Object> claims, String alg, String kid, PrivateKey key, String jca)
            throws Exception {
        return sign(claims, alg, kid, key, jca, "JWT");
    }

    /** As {@link #sign(Map, String, String, PrivateKey, String)}, with the header's {@code typ} chosen. */
    public static String sign(Map<String, Object> claims, String alg, String kid, PrivateKey key, String jca,
                              String typ) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg);
        header.put("typ", typ);
        if (kid != null) {
            header.put("kid", kid);
        }
        String input = signingInput(header, claims);
        Signature signature = signature(jca);
        signature.initSign(key);
        signature.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
    }

    /**
     * The JWS signing input, {@code base64url(header) "." base64url(claims)}, for a test that signs it
     * some way {@link #sign} does not — an HMAC forgery, say.
     */
    public static String signingInput(Map<String, Object> header, Map<String, Object> claims) throws Exception {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString(JSON.writeValueAsBytes(header)) + "."
                + b64.encodeToString(JSON.writeValueAsBytes(claims));
    }

    /**
     * A JCA signature for {@code jca}. RSASSA-PSS needs its parameters set, which a name alone cannot
     * carry, so {@link #jcaFor} names it {@code RSASSA-PSS/<hash>} and this applies RFC 7518 §3.5's: MGF1
     * with the same hash, and a salt as long as the hash.
     */
    private static Signature signature(String jca) throws Exception {
        if (!jca.startsWith("RSASSA-PSS/")) {
            return Signature.getInstance(jca);
        }
        String hash = jca.substring("RSASSA-PSS/".length());
        int saltLength = switch (hash) {
            case "SHA-256" -> 32;
            case "SHA-384" -> 48;
            case "SHA-512" -> 64;
            default -> throw new IllegalArgumentException(jca);
        };
        Signature signature = Signature.getInstance("RSASSA-PSS");
        signature.setParameter(new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash), saltLength, 1));
        return signature;
    }

    /**
     * {@code key} as a public JWK (RFC 7518 §6): EC on P-256, P-384 or P-521, or RSA. Coordinates are
     * written at their curve's full length, as §6.2.1.2 requires.
     */
    public static Map<String, Object> publicJwk(PublicKey key) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        Map<String, Object> jwk = new LinkedHashMap<>();
        if (key instanceof ECPublicKey ec) {
            int bits = ec.getParams().getCurve().getField().getFieldSize();
            int length = (bits + 7) / 8;
            jwk.put("kty", "EC");
            jwk.put("crv", switch (bits) {
                case 256 -> "P-256";
                case 384 -> "P-384";
                case 521 -> "P-521";
                default -> throw new IllegalArgumentException("unsupported curve: " + bits + " bits");
            });
            jwk.put("x", b64.encodeToString(fixedLength(ec.getW().getAffineX(), length)));
            jwk.put("y", b64.encodeToString(fixedLength(ec.getW().getAffineY(), length)));
        } else if (key instanceof RSAPublicKey rsa) {
            jwk.put("kty", "RSA");
            jwk.put("n", b64.encodeToString(unsigned(rsa.getModulus())));
            jwk.put("e", b64.encodeToString(unsigned(rsa.getPublicExponent())));
        } else {
            throw new IllegalArgumentException("unsupported key: " + key.getAlgorithm());
        }
        return jwk;
    }

    /** A big integer as exactly {@code length} unsigned big-endian bytes. */
    private static byte[] fixedLength(java.math.BigInteger value, int length) {
        byte[] raw = unsigned(value);
        byte[] fixed = new byte[length];
        System.arraycopy(raw, 0, fixed, length - raw.length, raw.length);
        return fixed;
    }

    /** A big integer as its unsigned big-endian bytes, without a leading sign byte. */
    private static byte[] unsigned(java.math.BigInteger value) {
        byte[] bytes = value.toByteArray();
        return bytes.length > 1 && bytes[0] == 0 ? java.util.Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
    }

    /**
     * The JCA signature algorithm a JOSE algorithm denotes (P1363 format for ECDSA). For {@code PS*} it is
     * {@code RSASSA-PSS/<hash>}, which only {@link #sign} understands.
     */
    public static String jcaFor(String alg) {
        return switch (alg) {
            case "EdDSA" -> "Ed25519";
            case "ES256" -> "SHA256withECDSAinP1363Format";
            case "ES384" -> "SHA384withECDSAinP1363Format";
            case "ES512" -> "SHA512withECDSAinP1363Format";
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            case "PS256" -> "RSASSA-PSS/SHA-256";
            case "PS384" -> "RSASSA-PSS/SHA-384";
            case "PS512" -> "RSASSA-PSS/SHA-512";
            default -> throw new IllegalArgumentException(alg);
        };
    }
}
