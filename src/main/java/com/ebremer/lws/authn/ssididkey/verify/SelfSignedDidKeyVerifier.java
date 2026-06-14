/*
 * Copyright Erich Bremer.
 *
 * Validates a self-issued did:key JWT as an LWS authentication credential, per
 * https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/
 *
 * Algorithm:
 *   1. Reject alg == "none".
 *   2. The credential is self-issued: sub == iss == client_id, and is a did:key URI.
 *   3. Decode the public key directly from the did:key identifier (no dereferencing).
 *   4. Validate the JWT signature against that key (RFC 7515 §5.2).
 *   5. Ensure the token is not expired, and carries an audience.
 *
 * The verifier is self-contained: no session, no network, no document. Signature verification uses
 * the JDK in the JOSE signature format (EdDSA for Ed25519, ES256/P1363 for P-256).
 */
package com.ebremer.lws.authn.ssididkey.verify;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;

import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.ssididkey.DidKey;
import com.ebremer.lws.authn.ssididkey.DidKeyConstants;

/**
 * @author Erich Bremer
 */
public class SelfSignedDidKeyVerifier {

    public DidKeyVerificationResult verify(String credential) {
        DidKeyVerificationResult result = new DidKeyVerificationResult();
        try {
            JWSInput jws = new JWSInput(credential);
            JWSHeader header = jws.getHeader();
            JsonWebToken token = JsonSerialization.readValue(jws.getContent(), JsonWebToken.class);

            String sub = token.getSubject();
            String iss = token.getIssuer();
            String clientId = asString(token.getOtherClaims().get("client_id"));
            result.setSubject(sub);

            // 1. alg must not be "none"
            String alg = header.getRawAlgorithm();
            boolean algOk = alg != null && !"none".equalsIgnoreCase(alg);
            result.check("signingAlgorithmNotNone", algOk);
            if (!algOk) {
                result.error("Credential MUST NOT use 'none' as the signing algorithm");
                return result.fail();
            }

            // 2. self-issued did:key
            boolean selfIssued = sub != null && !sub.isBlank() && sub.equals(iss) && sub.equals(clientId);
            result.check("selfIssued", selfIssued);
            if (!selfIssued) {
                result.error("Claims 'sub', 'iss' and 'client_id' MUST all use the same URI "
                        + "(sub=" + sub + ", iss=" + iss + ", client_id=" + clientId + ")");
                return result.fail();
            }
            boolean isDidKey = sub.startsWith(DidKeyConstants.DID_KEY_PREFIX);
            result.check("subjectIsDidKey", isDidKey);
            if (!isDidKey) {
                result.error("Subject is not a did:key identifier");
                return result.fail();
            }

            // 3. decode the key from the identifier itself
            DidKey.DecodedKey decoded;
            try {
                decoded = DidKey.decode(sub);
            } catch (Exception e) {
                result.check("keyDecodedFromDid", false);
                result.error("Could not decode the public key from the did:key: " + e.getMessage());
                return result.fail();
            }
            result.check("keyDecodedFromDid", true);
            result.setKeyType(decoded.keyType());

            boolean algMatches = decoded.jwsAlgorithm().equals(alg);
            result.check("algorithmMatchesKey", algMatches);
            if (!algMatches) {
                result.error("JWT 'alg' " + alg + " does not match the did:key key type " + decoded.keyType()
                        + " (expected " + decoded.jwsAlgorithm() + ")");
                return result.fail();
            }

            // 4. signature
            boolean signatureValid = verifySignature(alg, decoded.publicKey(), jws);
            result.check("signatureValid", signatureValid);
            if (!signatureValid) {
                result.error("Credential signature is invalid");
                return result.fail();
            }

            // 5. expiry + audience. Require 'exp' explicitly: Keycloak's isActive() treats a missing
            // exp as "never expires", which would make a captured credential replayable forever.
            Long exp = token.getExp();
            boolean notExpired = exp != null && exp != 0 && token.isActive();
            result.check("notExpired", notExpired);
            if (!notExpired) {
                result.error(exp == null || exp == 0
                        ? "Credential is missing the required 'exp' claim"
                        : "Credential is expired or not yet valid");
                return result.fail();
            }
            String[] aud = token.getAudience();
            boolean audiencePresent = aud != null && aud.length > 0;
            result.check("audiencePresent", audiencePresent);
            if (!audiencePresent) {
                result.error("Credential is missing the required 'aud' claim");
                return result.fail();
            }

            result.setValid(result.getErrors().isEmpty());
        } catch (Exception e) {
            result.error(e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage()));
            return result.fail();
        }
        return result;
    }

    /** Verifies the JWS signature with the JDK, in the JOSE signature format. */
    public static boolean verifySignature(String alg, PublicKey publicKey, JWSInput jws) throws Exception {
        Signature signature;
        switch (alg) {
            case "EdDSA" -> signature = Signature.getInstance("Ed25519");
            case "ES256" -> signature = Signature.getInstance("SHA256withECDSAinP1363Format");
            default -> {
                return false;
            }
        }
        signature.initVerify(publicKey);
        signature.update(jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8));
        return signature.verify(jws.getSignature());
    }

    private static String asString(Object value) {
        return value == null ? null : value.toString();
    }
}
