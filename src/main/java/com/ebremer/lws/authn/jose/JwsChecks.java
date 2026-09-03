/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Checks shared by the three JWT-based authentication suites, so OpenID, self-signed CID and
 * did:key cannot drift apart on the parts of RFC 7515 they all have to get right.
 */
package com.ebremer.lws.authn.jose;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.util.JsonSerialization;

/**
 * @author Erich Bremer
 */
public final class JwsChecks {

    private JwsChecks() {
    }

    /**
     * The {@code crit} header parameters of a JWS, or an empty list when there are none.
     *
     * <p>RFC 7515 §4.1.11 makes {@code crit} a list of extensions the recipient <em>must</em>
     * understand, and §5.2 — the validation algorithm both self-signed suites cite normatively —
     * requires a verifier to reject a JWS carrying any it does not. This provider implements no JWS
     * extensions, so any {@code crit} at all is grounds for rejection.</p>
     *
     * <p>Read from the raw encoded header rather than from Keycloak's {@code JWSHeader}, which is
     * annotated {@code @JsonIgnoreProperties(ignoreUnknown = true)} and therefore drops {@code crit}
     * silently — precisely the failure mode the header exists to prevent.</p>
     */
    public static List<String> criticalHeaders(JWSInput jws) {
        List<String> critical = new ArrayList<>();
        if (jws == null || jws.getEncodedHeader() == null) {
            return critical;
        }
        JsonNode header;
        try {
            byte[] raw = Base64.getUrlDecoder().decode(jws.getEncodedHeader());
            header = JsonSerialization.mapper.readTree(new String(raw, StandardCharsets.UTF_8));
        } catch (Exception unreadable) {
            // An unreadable header is not this method's failure to report; the signature check will
            // reject it. Report "no critical headers" and let validation continue to that point.
            return critical;
        }
        JsonNode crit = header == null ? null : header.get("crit");
        if (crit == null || crit.isNull()) {
            return critical;
        }
        if (crit.isArray()) {
            crit.forEach(name -> critical.add(name.asText()));
            if (critical.isEmpty()) {
                // RFC 7515 §4.1.11: the value MUST be a non-empty array. An empty one is malformed,
                // so name it rather than silently treating the token as extension-free.
                critical.add("(empty crit array)");
            }
        } else {
            critical.add("(crit is not an array)");
        }
        return critical;
    }

    /**
     * True iff the JOSE {@code alg} is an asymmetric signature algorithm whose key type matches
     * {@code key}.
     *
     * <p>Pinning the token's declared algorithm to the key actually in hand blocks algorithm
     * confusion: symmetric ({@code HS*}), {@code none} and unknown algorithms never match, so an
     * RSA or EC public key can never be pressed into service as an HMAC secret.</p>
     */
    public static boolean algMatchesKey(String alg, PublicKey key) {
        if (alg == null || key == null) {
            return false;
        }
        String keyType = key.getAlgorithm();
        if (alg.startsWith("RS") || alg.startsWith("PS")) {   // RSASSA-PKCS1-v1_5 / RSASSA-PSS
            return "RSA".equals(keyType);
        }
        if (alg.startsWith("ES")) {                           // ECDSA
            return "EC".equals(keyType) || "ECDSA".equals(keyType);
        }
        if ("EdDSA".equals(alg) || alg.startsWith("Ed")) {    // Edwards-curve EdDSA
            return "EdDSA".equals(keyType) || "Ed25519".equals(keyType) || "Ed448".equals(keyType);
        }
        return false;
    }

    /** True iff {@code audience} contains {@code expected}. */
    public static boolean audienceIncludes(String[] audience, String expected) {
        if (audience == null || expected == null) {
            return false;
        }
        for (String value : audience) {
            if (expected.equals(value)) {
                return true;
            }
        }
        return false;
    }
}
