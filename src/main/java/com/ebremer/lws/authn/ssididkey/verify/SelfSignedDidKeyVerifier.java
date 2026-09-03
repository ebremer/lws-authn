/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Validates a self-issued did:key JWT as an LWS authentication credential, per
 * https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/
 *
 * Algorithm:
 *   1. Reject alg == "none", and any critical header this provider does not implement.
 *   2. The credential is self-issued: sub == iss == client_id, and is a canonically encoded did:key.
 *   3. Decode the public key directly from the did:key identifier (no dereferencing).
 *   4. Validate the JWT signature against that key (RFC 7515 §5.2).
 *   5. Ensure the token carries iat and exp, is not expired, and is restricted to the target audience.
 *
 * The verifier is self-contained: no session, no network, no document. Signature verification uses
 * the JDK in the JOSE signature format (EdDSA for Ed25519, ES256/P1363 for P-256).
 */
package com.ebremer.lws.authn.ssididkey.verify;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.jose.JwsChecks;
import com.ebremer.lws.authn.ssididkey.DidKey;
import com.ebremer.lws.authn.ssididkey.DidKeyConstants;
import com.ebremer.lws.authn.verify.ReplayCache;
import com.ebremer.lws.authn.verify.Trace;

/**
 * @author Erich Bremer
 */
public class SelfSignedDidKeyVerifier {

    private static final Logger log = Logger.getLogger(SelfSignedDidKeyVerifier.class);

    private final ReplayCache replayCache;

    public SelfSignedDidKeyVerifier() {
        this(null);
    }

    /**
     * @param replayCache optional, and normally {@code null} — see {@link ReplayCache}.
     */
    public SelfSignedDidKeyVerifier(ReplayCache replayCache) {
        this.replayCache = replayCache;
    }

    public DidKeyVerificationResult verify(String credential) {
        return verify(credential, null);
    }

    /**
     * @param credential       the self-issued JWT
     * @param expectedAudience the authorization server this verifier speaks for. The suite says the
     *                         {@code aud} claim "MUST include the target authorization server"; without
     *                         knowing which one that is, only the presence of an audience can be checked.
     */
    public DidKeyVerificationResult verify(String credential, String expectedAudience) {
        DidKeyVerificationResult result = new DidKeyVerificationResult();
        result.setTraceId(Trace.newId());
        result.setTokenType(DidKeyConstants.TOKEN_TYPE_JWT);
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

            // RFC 7515 5.2, cited normatively by this suite: reject critical headers we do not implement.
            List<String> critical = JwsChecks.criticalHeaders(jws);
            result.check("noUnsupportedCriticalHeaders", critical.isEmpty());
            if (!critical.isEmpty()) {
                result.error("Credential carries unsupported critical header parameters: " + critical);
                return result.fail();
            }

            boolean typeOk = JwsChecks.typeIsJwtOrAbsent(header.getType());
            result.check("typeIsJwt", typeOk);
            if (!typeOk) {
                result.error("Credential 'typ' header is not a JWT type");
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
            result.setClient(clientId);
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
            boolean notExpired = JwsChecks.withinValidityWindow(token);
            result.check("notExpired", notExpired);
            if (!notExpired) {
                result.error(exp == null || exp == 0
                        ? "Credential is missing the required 'exp' claim"
                        : "Credential is expired or not yet valid");
                return result.fail();
            }
            // "The JWT MUST include an `iat` (issued at) claim."
            Long iat = token.getIat();
            boolean issuedAtPresent = iat != null && iat != 0;
            result.check("issuedAtPresent", issuedAtPresent);
            if (!issuedAtPresent) {
                result.error("Credential is missing the required 'iat' claim");
                return result.fail();
            }

            String[] aud = token.getAudience();
            boolean audiencePresent = aud != null && aud.length > 0;
            result.check("audiencePresent", audiencePresent);
            if (!audiencePresent) {
                result.error("Credential is missing the required 'aud' claim");
                return result.fail();
            }
            if (expectedAudience != null && !expectedAudience.isBlank()) {
                boolean audienceMatched = JwsChecks.audienceIncludes(aud, expectedAudience);
                result.check("audienceMatched", audienceMatched);
                if (!audienceMatched) {
                    result.error("Credential 'aud' does not include the target audience <" + expectedAudience + ">");
                    return result.fail();
                }
            }

            if (replayCache != null) {
                boolean firstSighting = replayCache.firstSighting(iss, token.getId());
                result.check("notReplayed", firstSighting);
                if (!firstSighting) {
                    result.error("Credential 'jti' has already been verified within the replay window");
                    return result.fail();
                }
            }

            result.setValid(result.getErrors().isEmpty());
        } catch (Exception e) {
            log.debugf(e, "[%s] LWS did:key credential verification failed", result.getTraceId());
            result.error("Credential could not be validated");
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
            case "ES384" -> signature = Signature.getInstance("SHA384withECDSAinP1363Format");
            case "ES512" -> signature = Signature.getInstance("SHA512withECDSAinP1363Format");
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
