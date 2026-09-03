/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Public-only projection of a JSON Web Key, applied to every JWK this provider is about to publish in
 * a controlled identifier document.
 */
package com.ebremer.lws.authn.jose;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.util.JsonSerialization;

/**
 * Strips a JWK down to its public members, and refuses outright any JWK that carries private key
 * material.
 *
 * <p>W3C Controlled Identifiers 1.0 requires that a {@code publicKeyJwk} map <em>"MUST NOT include any
 * members of the private information class, such as {@code d}"</em>. The keys published by this
 * provider come from an operator-managed user attribute, so a single mis-pasted key pair would
 * otherwise serve an agent's private key from a world-readable URL.</p>
 *
 * <p>A JWK containing any private member is <em>rejected</em> rather than trimmed: if the private half
 * reached the server, the key is already compromised and silently publishing its public half would
 * hide that. The operator sees a warning and the key simply does not appear in the document.</p>
 *
 * @author Erich Bremer
 */
public final class PublicJwk {

    private PublicJwk() {
    }

    /**
     * Members that carry private/secret key material across the JWK key types of RFC 7518: RSA
     * ({@code d, p, q, dp, dq, qi, oth}), EC and OKP ({@code d}) and symmetric ({@code k}).
     */
    public static final Set<String> PRIVATE_MEMBERS = Set.of("d", "p", "q", "dp", "dq", "qi", "k", "oth");

    /**
     * Members that may be published, in the order they are emitted. RFC 7517 common parameters plus the
     * public key material of the RSA, EC and OKP key types (RFC 7518).
     */
    public static final List<String> PUBLIC_MEMBERS = List.of(
            "kty", "kid", "use", "key_ops", "alg", "crv", "x", "y", "n", "e",
            "x5u", "x5c", "x5t", "x5t#S256");

    /**
     * Returns the publishable projection of {@code jwk}, or empty when it must not be published at all.
     *
     * <p>Empty is returned when the value is not a JSON object, when it carries any
     * {@linkplain #PRIVATE_MEMBERS private member}, when it has no {@code kty}, or when {@code kty} is
     * {@code oct} (a symmetric key is secret material by definition and can never appear in a
     * controlled identifier document).</p>
     */
    public static Optional<JsonNode> sanitize(JsonNode jwk) {
        if (jwk == null || !jwk.isObject()) {
            return Optional.empty();
        }
        if (!privateMembers(jwk).isEmpty()) {
            return Optional.empty();
        }
        String kty = jwk.path("kty").asText(null);
        if (kty == null || kty.isBlank() || "oct".equalsIgnoreCase(kty)) {
            return Optional.empty();
        }
        ObjectNode out = JsonSerialization.mapper.createObjectNode();
        for (String member : PUBLIC_MEMBERS) {
            if (jwk.hasNonNull(member)) {
                out.set(member, jwk.get(member));
            }
        }
        return Optional.of(out);
    }

    /** The private members present in {@code jwk}, in a stable order; empty when there are none. */
    public static List<String> privateMembers(JsonNode jwk) {
        if (jwk == null || !jwk.isObject()) {
            return List.of();
        }
        return PRIVATE_MEMBERS.stream().filter(jwk::has).sorted().toList();
    }

    /**
     * A short, log-safe explanation of why {@link #sanitize} rejected a value. Names the offending
     * members but never their values.
     */
    public static String describeRejection(JsonNode jwk) {
        if (jwk == null || !jwk.isObject()) {
            return "value is not a JWK JSON object";
        }
        List<String> priv = privateMembers(jwk);
        if (!priv.isEmpty()) {
            return "JWK contains private key material (" + String.join(", ", priv)
                    + ") and MUST NOT be published; register only the public JWK";
        }
        String kty = jwk.path("kty").asText(null);
        if (kty == null || kty.isBlank()) {
            return "JWK has no 'kty' member";
        }
        if ("oct".equalsIgnoreCase(kty)) {
            return "JWK is a symmetric key (kty=oct) and MUST NOT be published";
        }
        return "JWK is not publishable";
    }
}
