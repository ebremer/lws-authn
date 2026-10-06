/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * JWS signature verification with the JDK alone, in the JOSE signature format.
 */
package com.ebremer.lws.authn.jose;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;

import org.keycloak.jose.jws.JWSInput;

/**
 * Verifies a JWS signature (RFC 7515 §5.2) without a Keycloak session.
 *
 * <p>Used by the self-signed CID verifier when it runs outside Keycloak (its unit tests). Inside
 * Keycloak that verifier goes through Keycloak's own {@code SignatureProvider}, so the crypto provider
 * an operator configured — including FIPS — is the one that decides.</p>
 *
 * <p>Only the asymmetric algorithms a self-issued credential can use are supported: EdDSA, ES*, and
 * RS* and PS* for an RSA {@code JsonWebKey}. Everything else, {@code none} and {@code HS*} included, verifies as
 * {@code false}.</p>
 *
 * @author Erich Bremer
 */
public final class JwsSignatures {

    private JwsSignatures() {
    }

    /** Verifies the JWS signature with the JDK, in the JOSE signature format (P1363 for ECDSA). */
    public static boolean verify(String alg, PublicKey publicKey, JWSInput jws) throws Exception {
        if (alg == null || publicKey == null || jws == null) {
            return false;
        }
        Signature signature;
        switch (alg) {
            case "EdDSA" -> signature = Signature.getInstance("Ed25519");
            case "ES256" -> signature = Signature.getInstance("SHA256withECDSAinP1363Format");
            case "ES384" -> signature = Signature.getInstance("SHA384withECDSAinP1363Format");
            case "ES512" -> signature = Signature.getInstance("SHA512withECDSAinP1363Format");
            case "RS256" -> signature = Signature.getInstance("SHA256withRSA");
            case "RS384" -> signature = Signature.getInstance("SHA384withRSA");
            case "RS512" -> signature = Signature.getInstance("SHA512withRSA");
            case "PS256" -> signature = pss("SHA-256", 32);
            case "PS384" -> signature = pss("SHA-384", 48);
            case "PS512" -> signature = pss("SHA-512", 64);
            default -> {
                return false;
            }
        }
        signature.initVerify(publicKey);
        signature.update(jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8));
        return signature.verify(jws.getSignature());
    }

    /** RSASSA-PSS as RFC 7518 §3.5 fixes it: MGF1 with the same hash, and a salt as long as the hash. */
    private static Signature pss(String hash, int saltLength) throws Exception {
        Signature signature = Signature.getInstance("RSASSA-PSS");
        signature.setParameter(new java.security.spec.PSSParameterSpec(hash, "MGF1",
                new java.security.spec.MGF1ParameterSpec(hash), saltLength, 1));
        return signature;
    }
}
