/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Turning a JWK `kid` into the fragment of a verification method's IRI.
 */
package com.ebremer.lws.authn.jose;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Encodes a JWK {@code kid} for use as the fragment of a verification method identifier.
 *
 * <p>A controlled identifier document names each verification method
 * {@code <subject>#<kid>}, and the {@code kid} is operator-supplied free text: a JWK's
 * {@code kid} is "a case-sensitive string" (RFC 7517 §4.5) with no syntax at all. Concatenated
 * unescaped, a {@code kid} containing a space, a {@code #}, a {@code /} or a {@code ?} produces
 * something that is not an IRI — Jena refuses to write it and the CID endpoint answers 500, so one
 * badly-named key takes out the whole document for every other key on that user.</p>
 *
 * <p>Everything outside RFC 3986 {@code unreserved} is percent-encoded. That is stricter than the
 * {@code fragment} production needs — {@code :} and {@code @} would be legal literally — but the
 * encoded form is unambiguous, round-trips through {@link java.net.URLDecoder}, and does not depend on
 * a reader agreeing about which sub-delimiters are safe.</p>
 *
 * @author Erich Bremer
 */
public final class KeyIdFragment {

    private KeyIdFragment() {
    }

    /**
     * Longest {@code kid} that will be turned into a fragment. RFC 7517 sets no limit; this one is
     * about four times the length of any {@code kid} in practice (a base64url SHA-256 thumbprint is 43
     * characters) and stops an absurd attribute value from producing an absurd IRI.
     */
    public static final int MAX_KID_LENGTH = 200;

    private static final String UNRESERVED_EXTRA = "-._~";
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    /**
     * The percent-encoded fragment for {@code kid}, or empty when it cannot be one.
     *
     * <p>Refused rather than encoded: a {@code kid} that is absent or blank (there is nothing to name
     * the method after), one longer than {@link #MAX_KID_LENGTH}, and one containing an unpaired
     * surrogate or a code point that is not valid text — those cannot be encoded to UTF-8 without
     * silently becoming a different string, and a verification method whose identifier is not the one
     * the key holder meant is worse than a method with no identifier at all.</p>
     *
     * <p>A caller that gets {@link Optional#empty()} should publish the method without an {@code id}
     * (as a blank node in RDF), which is what this document already does for a JWK with no
     * {@code kid}: the key is still usable, it just cannot be referenced by IRI.</p>
     */
    public static Optional<String> encode(String kid) {
        if (kid == null || kid.isBlank() || kid.length() > MAX_KID_LENGTH || !isWellFormedText(kid)) {
            return Optional.empty();
        }
        StringBuilder out = new StringBuilder(kid.length() + 8);
        for (byte b : kid.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (b & 0xFF);
            if (isUnreserved(c)) {
                out.append(c);
            } else {
                out.append('%').append(HEX[(b >> 4) & 0x0F]).append(HEX[b & 0x0F]);
            }
        }
        return Optional.of(out.toString());
    }

    /**
     * The full verification method identifier {@code <subject>#<encoded kid>}, or empty when the
     * {@code kid} cannot be encoded.
     */
    public static Optional<String> methodId(String subject, String kid) {
        if (subject == null || subject.isBlank()) {
            return Optional.empty();
        }
        return encode(kid).map(fragment -> subject + "#" + fragment);
    }

    /**
     * The {@code kid} a fragment names: percent-decoded when it decodes cleanly, and returned
     * unchanged when it does not.
     *
     * <p>Used when matching a credential's {@code kid} against the identifier of a verification method
     * in a document this provider did not write. Percent-encoding a fragment is the conventional thing
     * to do and other implementations do it too, so a comparison that only ever looks at the raw
     * fragment would miss a method that is genuinely the one the credential names.</p>
     */
    public static String decode(String fragment) {
        if (fragment == null || fragment.indexOf('%') < 0) {
            return fragment;
        }
        try {
            return java.net.URLDecoder.decode(fragment.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (RuntimeException notEncoded) {
            return fragment;
        }
    }

    private static boolean isUnreserved(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || UNRESERVED_EXTRA.indexOf(c) >= 0;
    }

    /** False if the string contains an unpaired surrogate, which UTF-8 encoding would replace. */
    private static boolean isWellFormedText(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(i + 1))) {
                    return false;
                }
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return false;
            }
        }
        return true;
    }
}
