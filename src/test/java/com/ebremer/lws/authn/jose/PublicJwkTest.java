/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

/**
 * P0-1. The self-signed-CID endpoint publishes JWKs taken from an operator-managed user attribute, so
 * the projection applied on the way out is the only thing standing between a mis-pasted key pair and a
 * private key served at a world-readable URL. CID 1.0: a {@code publicKeyJwk} map "MUST NOT include any
 * members of the private information class, such as {@code d}".
 */
class PublicJwkTest {

    private static JsonNode json(String s) throws Exception {
        return JsonSerialization.mapper.readTree(s);
    }

    @Test
    void keepsThePublicMembersOfAnEcKey() throws Exception {
        JsonNode sanitized = PublicJwk.sanitize(json(
                "{\"kid\":\"k1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"x\":\"XX\",\"y\":\"YY\"}"))
                .orElseThrow();
        assertEquals("EC", sanitized.path("kty").asText());
        assertEquals("k1", sanitized.path("kid").asText());
        assertEquals("P-256", sanitized.path("crv").asText());
        assertEquals("XX", sanitized.path("x").asText());
        assertEquals("YY", sanitized.path("y").asText());
    }

    @Test
    void dropsMembersThatAreNotPartOfAJwk() throws Exception {
        JsonNode sanitized = PublicJwk.sanitize(json(
                "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"XX\",\"y\":\"YY\",\"note\":\"hello\"}")).orElseThrow();
        assertFalse(sanitized.has("note"), "unknown members must not be republished verbatim");
    }

    /** An EC or OKP private key: 'd' is the private scalar. */
    @Test
    void rejectsAnEcPrivateKey() throws Exception {
        JsonNode jwk = json("{\"kid\":\"k1\",\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"XX\",\"y\":\"YY\",\"d\":\"SECRET\"}");
        assertEquals(Optional.empty(), PublicJwk.sanitize(jwk),
                "a JWK containing 'd' must never be published, not even with 'd' stripped");
        assertTrue(PublicJwk.describeRejection(jwk).contains("private key material"));
    }

    /** Every RSA private member, one at a time — a partial key pair is still a compromised key. */
    @Test
    void rejectsEveryRsaPrivateMember() throws Exception {
        for (String member : new String[]{"d", "p", "q", "dp", "dq", "qi", "oth"}) {
            JsonNode jwk = json("{\"kty\":\"RSA\",\"n\":\"NN\",\"e\":\"AQAB\",\"" + member + "\":\"SECRET\"}");
            assertEquals(Optional.empty(), PublicJwk.sanitize(jwk), "must reject a JWK carrying '" + member + "'");
        }
    }

    /** A symmetric key is secret material by definition and can never appear in a public document. */
    @Test
    void rejectsSymmetricKeys() throws Exception {
        assertEquals(Optional.empty(), PublicJwk.sanitize(json("{\"kty\":\"oct\",\"k\":\"SECRET\"}")));
        assertEquals(Optional.empty(), PublicJwk.sanitize(json("{\"kty\":\"oct\",\"kid\":\"k1\"}")),
                "kty=oct is not publishable even with no key value present");
    }

    @Test
    void rejectsMalformedValues() throws Exception {
        assertEquals(Optional.empty(), PublicJwk.sanitize(null));
        assertEquals(Optional.empty(), PublicJwk.sanitize(json("\"not an object\"")));
        assertEquals(Optional.empty(), PublicJwk.sanitize(json("{\"kid\":\"k1\"}")), "no kty");
    }

    /** The rejection text is for a log line: it names the offending members, never their values. */
    @Test
    void rejectionTextNeverRepeatsTheSecret() throws Exception {
        String description = PublicJwk.describeRejection(
                json("{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"XX\",\"y\":\"YY\",\"d\":\"SUPERSECRET\"}"));
        assertFalse(description.contains("SUPERSECRET"), "the private value must not reach the log: " + description);
    }
}
