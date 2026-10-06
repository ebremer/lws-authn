/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Checks shared by the two JWT-based authentication suites, so OpenID and self-signed CID cannot
 * drift apart on the parts of RFC 7515 they both have to get right.
 */
package com.ebremer.lws.authn.jose;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.crypto.KeyType;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.config.ServerSettings;

/**
 * @author Erich Bremer
 */
public final class JwsChecks {

    private JwsChecks() {
    }

    /** RFC 7515 §7.1: three base64url segments — no padding, whitespace or any other character. */
    private static final Pattern COMPACT_SERIALIZATION =
            Pattern.compile("([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)");

    /**
     * True iff {@code credential} is a JWS in compact serialization that every base64url decoder reads
     * the same way.
     *
     * <p>RFC 7515 §5.2 decodes each part "following the restriction that no line breaks, whitespace, or
     * other additional characters have been used", and a JWS that does not decode "MUST be rejected".
     * Keycloak's own decoder is lenient — it maps {@code +} and {@code /}, and stops at {@code =} — so a
     * header could say one thing to it and another to a strict reader. A signed header carrying
     * {@code "crit": ["urn:x"]} with {@code =junk} appended verified, with
     * {@code noUnsupportedCriticalHeaders: true} (R-24). A segment of a length no base64 encoding has
     * (one more than a multiple of four) is refused here too.</p>
     */
    public static boolean compactSerializationWellFormed(String credential) {
        if (credential == null) {
            return false;
        }
        Matcher segments = COMPACT_SERIALIZATION.matcher(credential);
        if (!segments.matches()) {
            return false;
        }
        for (int i = 1; i <= 3; i++) {
            if (segments.group(i).length() % 4 == 1) {
                return false;
            }
        }
        return true;
    }

    /** The registered claims RFC 7519 makes a NumericDate (§4.1.4-4.1.6). */
    private static final List<String> DATE_CLAIMS = List.of("exp", "nbf", "iat");

    /**
     * The date claims in {@code payload} that are present but not JSON numbers.
     *
     * <p>RFC 7519 §2: a NumericDate is "a JSON numeric value". Jackson reads {@code "exp": "1900000000"}
     * into the same {@code Long} as the number, so the typed token cannot tell them apart and the raw
     * payload is read instead (R-24). A fractional value is a JSON number, and §2 says "non-integer
     * values can be represented", so it is accepted; the token reads it to the whole second below,
     * which can only bring {@code exp} earlier, and {@code iat} or {@code nbf} by under a second.</p>
     *
     * @return the offending claim names, empty when there are none
     * @throws java.io.IOException if the payload is not JSON
     */
    public static List<String> nonNumericDates(byte[] payload) throws java.io.IOException {
        JsonNode claims = JsonSerialization.mapper.readTree(payload);
        List<String> wrong = new ArrayList<>();
        if (claims != null && claims.isObject()) {
            for (String name : DATE_CLAIMS) {
                JsonNode value = claims.get(name);
                if (value != null && !value.isNumber()) {
                    wrong.add(name);
                }
            }
        }
        return wrong;
    }

    /**
     * True iff {@code signature} is as long as {@code alg} requires, for the algorithms where the
     * signature provider does not check that itself.
     *
     * <p>RFC 7518 §3.4: an {@code ES256} signature "MUST be a 64-octet sequence. If it is not … the
     * validation has failed" — 96 octets for {@code ES384}, 132 for {@code ES512}. Keycloak's ECDSA
     * verifier converts R‖S to DER from the first bytes and ignores the rest, so an 80-byte
     * {@code ES256} signature verified inside Keycloak while the JDK path refused it (R-24). Other
     * algorithms are left to their providers, which do check.</p>
     */
    public static boolean signatureLengthValid(String alg, byte[] signature) {
        int required = alg == null ? -1 : switch (alg) {
            case "ES256" -> 64;
            case "ES384" -> 96;
            case "ES512" -> 132;
            default -> -1;
        };
        return required < 0 || (signature != null && signature.length == required);
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
            // RFC 7515 §5.2 step 2: a header that does not decode means the JWS "MUST be rejected".
            // This used to report "no critical headers" here, while Keycloak's lenient decoder read the
            // same header — crit and all — once a trailing "=junk" was stripped (R-24).
            critical.add("(header is not base64url-encoded JSON)");
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
     *
     * <p>For ECDSA the curve is pinned too. RFC 7518 §3.4 defines each {@code ES*} algorithm as one
     * curve and one hash — {@code ES256} is P-256 with SHA-256, {@code ES384} P-384, {@code ES512}
     * P-521 — and a JCA verifier will happily check a SHA-256 signature made with a P-384 key, which
     * is a valid ECDSA signature but not a valid {@code ES256} one.</p>
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
            if (!("EC".equals(keyType) || "ECDSA".equals(keyType))) {
                return false;
            }
            int expectedFieldSize = switch (alg) {
                case "ES256" -> 256;
                case "ES384" -> 384;
                case "ES512" -> 521;
                default -> -1;                                // ES256K and the like: not a curve this provider supports
            };
            if (expectedFieldSize < 0) {
                return false;
            }
            return !(key instanceof java.security.interfaces.ECKey ecKey)
                    || ecKey.getParams().getCurve().getField().getFieldSize() == expectedFieldSize;
        }
        if ("EdDSA".equals(alg) || alg.startsWith("Ed")) {    // Edwards-curve EdDSA
            return "EdDSA".equals(keyType) || "Ed25519".equals(keyType) || "Ed448".equals(keyType);
        }
        return false;
    }

    /**
     * Leeway allowed on {@code exp} and {@code nbf}. Both JWT suites say a verifier "MAY provide
     * for some small leeway to account for clock skew"; Keycloak's own {@code isActive()} allows 10
     * seconds on {@code nbf} and none at all on {@code exp}, so a credential could be refused by a
     * server whose clock ran a second fast. The 60-second default matches what the SAML verifier
     * applies; configure it as {@code clock-skew-seconds} (see {@link ServerSettings}).
     */
    public static long clockSkewSeconds() {
        return ServerSettings.clockSkewSeconds();
    }

    /**
     * JOSE {@code typ} values this provider accepts when the header declares one (RFC 8725 §3.11).
     *
     * <p>Not {@code at+jwt}, which this set once included. That is RFC 9068's marker for an OAuth
     * access token, and explicit typing exists precisely so that a token minted for one purpose cannot
     * be presented as another: an access token is not an authentication credential in either JWT
     * suite (R-05).</p>
     */
    private static final Set<String> ACCEPTED_TYPES = Set.of("jwt", "application/jwt");

    /**
     * True iff {@code token} is inside its validity window, allowing {@link #clockSkewSeconds()} of
     * clock skew at both ends.
     *
     * <p>An absent or zero {@code exp} is <em>not</em> valid: Keycloak's {@code isActive()} treats a
     * missing expiry as "never expires", which would make a captured credential replayable forever.</p>
     */
    public static boolean withinValidityWindow(JsonWebToken token) {
        if (token == null) {
            return false;
        }
        Long exp = token.getExp();
        if (exp == null || exp == 0) {
            return false;
        }
        long now = Instant.now().getEpochSecond();
        long skew = clockSkewSeconds();
        if (now >= exp + skew) {
            return false;
        }
        Long notBefore = token.getNbf();
        return notBefore == null || notBefore == 0 || now >= notBefore - skew;
    }

    /**
     * True iff the JOSE {@code typ} header is absent or names a JWT.
     *
     * <p>RFC 8725 §3.11 recommends explicit typing so a token minted for one purpose cannot be
     * presented as another. It is only a recommendation, and issuers legitimately omit {@code typ}, so
     * an absent value is accepted and a <em>wrong</em> one is not.</p>
     */
    public static boolean typeIsJwtOrAbsent(String typ) {
        return typ == null || typ.isBlank() || ACCEPTED_TYPES.contains(typ.trim().toLowerCase(java.util.Locale.ROOT));
    }

    /**
     * Keycloak's {@code KeyType} name for a JCA public key.
     *
     * <p>Not the same string as {@link PublicKey#getAlgorithm()}: a key built from a JWK by Keycloak's
     * own {@code JWKParser} reports {@code "ECDSA"}, while Keycloak's signature providers check for
     * {@code KeyType.EC} ({@code "EC"}) and refuse anything else with "Key with algorithm ES256 and
     * type ECDSA is incorrect for provider algorithm ES256". Passing the JCA name straight through
     * therefore made every EC-signed credential unverifiable — which is the algorithm the LWS suites'
     * own examples use.</p>
     */
    public static String keycloakKeyType(PublicKey key) {
        String algorithm = key == null ? null : key.getAlgorithm();
        if (algorithm == null) {
            return null;
        }
        if ("RSA".equals(algorithm)) {
            return KeyType.RSA;
        }
        if ("EC".equals(algorithm) || "ECDSA".equals(algorithm)) {
            return KeyType.EC;
        }
        if (algorithm.startsWith("Ed") || "EdDSA".equals(algorithm)) {
            return KeyType.OKP;
        }
        return algorithm;
    }

    /**
     * True iff {@code audience} names at least one audience and none of them is blank. A blank entry —
     * {@code "aud": [""]} — names nothing, and used to satisfy "present" on its own (R-16).
     */
    public static boolean audiencePresent(String[] audience) {
        if (audience == null || audience.length == 0) {
            return false;
        }
        for (String value : audience) {
            if (value == null || value.isBlank()) {
                return false;
            }
        }
        return true;
    }

    /**
     * True iff {@code token}'s {@code iat} is not in the future — allowing {@link #clockSkewSeconds()} —
     * and not after its own {@code exp} (R-28). A credential "issued" ten years from now, or after it
     * expires, was not issued by anything keeping time; both used to pass. Presence is checked
     * separately, so an absent {@code iat} passes here.
     */
    public static boolean issuedAtConsistent(JsonWebToken token) {
        Long iat = token == null ? null : token.getIat();
        if (iat == null || iat == 0) {
            return true;
        }
        if (iat > Instant.now().getEpochSecond() + clockSkewSeconds()) {
            return false;
        }
        Long exp = token.getExp();
        return exp == null || exp == 0 || iat <= exp;
    }

    /**
     * True iff {@code token}'s lifetime, {@code exp − iat}, is within the configured
     * {@code max-credential-lifetime-seconds}, or no maximum is configured (R-28). A missing {@code iat}
     * or {@code exp} passes here: each is required, and reported, by its own check.
     */
    public static boolean lifetimeWithinLimit(JsonWebToken token) {
        long max = ServerSettings.maxCredentialLifetimeSeconds();
        if (max <= 0 || token == null) {
            return true;
        }
        Long iat = token.getIat();
        Long exp = token.getExp();
        if (iat == null || iat == 0 || exp == null || exp == 0) {
            return true;
        }
        return exp - iat <= max;
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
