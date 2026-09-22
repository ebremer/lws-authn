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
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
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
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg);
        header.put("typ", "JWT");
        if (kid != null) {
            header.put("kid", kid);
        }
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String input = b64.encodeToString(JSON.writeValueAsBytes(header)) + "."
                + b64.encodeToString(JSON.writeValueAsBytes(claims));
        Signature signature = Signature.getInstance(jca);
        signature.initSign(key);
        signature.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + b64.encodeToString(signature.sign());
    }

    /** The JCA signature algorithm a JOSE algorithm denotes (P1363 format for ECDSA). */
    public static String jcaFor(String alg) {
        return switch (alg) {
            case "EdDSA" -> "Ed25519";
            case "ES256" -> "SHA256withECDSAinP1363Format";
            case "ES384" -> "SHA384withECDSAinP1363Format";
            case "ES512" -> "SHA512withECDSAinP1363Format";
            default -> throw new IllegalArgumentException(alg);
        };
    }
}
