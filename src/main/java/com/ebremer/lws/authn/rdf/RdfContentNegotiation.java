/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.rdf;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

/**
 * Content negotiation and cache headers for the served controlled identifier documents.
 *
 * <p>A controlled identifier document is a resource other people fetch, so it should behave like one:
 * honour the {@code Accept} header it was actually sent, say that its representation varies by it, and
 * give a caching client something to work with. Both suite drafts encourage verifiers to cache these
 * documents "to reduce unnecessary network requests and the associated metadata leakage", which needs
 * the server to say how.</p>
 *
 * @author Erich Bremer
 */
public final class RdfContentNegotiation {

    private RdfContentNegotiation() {
    }

    public static final String JSON_LD = "application/ld+json";
    public static final String TURTLE = "text/turtle";
    public static final String N_TRIPLES = "application/n-triples";
    public static final String RDF_XML = "application/rdf+xml";

    /**
     * The syntaxes served, in the order preferred when a client expresses no preference between them
     * (an {@code Accept} of {@code * / *}, or equal q-values). JSON-LD leads because it is the form
     * every LWS suite's example is written in.
     */
    public static final List<String> SUPPORTED = List.of(JSON_LD, TURTLE, N_TRIPLES, RDF_XML);

    /** How long a controlled identifier document may be cached, in seconds. */
    public static final long CACHE_SECONDS = 300;

    private record Preference(String type, String subtype, double quality, int order) {
    }

    /**
     * Picks the best supported media type for an {@code Accept} header.
     *
     * <p>The previous implementation asked whether the header <em>contained</em> each type name in a
     * fixed order, so {@code Accept: application/ld+json;q=1.0, text/turtle;q=0.1} returned Turtle —
     * the client's least-wanted choice — and an {@code Accept} naming nothing on offer silently got
     * JSON-LD instead of a 406.</p>
     *
     * @return the chosen media type, or {@code null} if the client accepts nothing this server serves
     */
    public static String best(String accept) {
        if (accept == null || accept.isBlank()) {
            return SUPPORTED.get(0);
        }
        List<Preference> preferences = parse(accept);
        if (preferences.isEmpty()) {
            return null;
        }
        String best = null;
        double bestQuality = 0;
        int bestOrder = Integer.MAX_VALUE;
        for (String candidate : SUPPORTED) {
            double quality = qualityOf(candidate, preferences);
            int order = SUPPORTED.indexOf(candidate);
            if (quality > 0 && (quality > bestQuality || (quality == bestQuality && order < bestOrder))) {
                best = candidate;
                bestQuality = quality;
                bestOrder = order;
            }
        }
        return best;
    }

    /** The q-value a parsed {@code Accept} assigns to {@code mediaType}; 0 means unacceptable. */
    private static double qualityOf(String mediaType, List<Preference> preferences) {
        String[] parts = mediaType.split("/", 2);
        double quality = 0;
        int specificity = -1;
        for (Preference preference : preferences) {
            int candidateSpecificity;
            if (preference.type().equals(parts[0]) && preference.subtype().equals(parts[1])) {
                candidateSpecificity = 2;
            } else if (preference.type().equals(parts[0]) && "*".equals(preference.subtype())) {
                candidateSpecificity = 1;
            } else if ("*".equals(preference.type()) && "*".equals(preference.subtype())) {
                candidateSpecificity = 0;
            } else {
                continue;
            }
            // RFC 9110 §12.5.1: the most specific match wins, regardless of the order it appears in.
            // Among equally specific matches — a media range repeated, which is malformed but happens —
            // take the most generous, so one unparseable q does not veto a well-formed duplicate.
            if (candidateSpecificity > specificity) {
                specificity = candidateSpecificity;
                quality = preference.quality();
            } else if (candidateSpecificity == specificity) {
                quality = Math.max(quality, preference.quality());
            }
        }
        return quality;
    }

    private static List<Preference> parse(String accept) {
        List<Preference> preferences = new ArrayList<>();
        int order = 0;
        for (String element : accept.split(",")) {
            String[] parts = element.trim().split(";");
            String mediaType = parts[0].trim().toLowerCase(Locale.ROOT);
            if (mediaType.isEmpty()) {
                continue;
            }
            String[] typeParts = mediaType.split("/", 2);
            if (typeParts.length != 2) {
                continue;
            }
            double quality = 1.0;
            for (int i = 1; i < parts.length; i++) {
                String parameter = parts[i].trim();
                if (parameter.regionMatches(true, 0, "q=", 0, 2)) {
                    try {
                        quality = Double.parseDouble(parameter.substring(2).trim());
                    } catch (NumberFormatException malformed) {
                        quality = 0; // an unparseable q is not a preference we can honour
                    }
                }
            }
            preferences.add(new Preference(typeParts[0], typeParts[1], quality, order++));
        }
        return preferences;
    }

    /**
     * A strong entity tag for a served representation. Derived from the bytes actually sent, so it
     * differs between syntaxes of the same document, as it must: they are different representations.
     */
    public static String entityTag(String body) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(body.getBytes(StandardCharsets.UTF_8));
            // Returned unquoted: JAX-RS wraps an EntityTag value in quotes when it writes the header,
            // so quoting here produces a doubly-quoted tag that no client's If-None-Match can match.
            return HexFormat.of().formatHex(digest, 0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 is required by every Java platform", e);
        }
    }

    /**
     * True iff an {@code If-None-Match} header matches {@code entityTag}.
     *
     * <p>The client echoes back what the header carried — quoted, and possibly weak — while
     * {@link #entityTag} is the bare value, so each candidate is unwrapped before comparing.</p>
     */
    public static boolean matches(String ifNoneMatch, String entityTag) {
        if (ifNoneMatch == null || entityTag == null) {
            return false;
        }
        for (String candidate : ifNoneMatch.split(",")) {
            String trimmed = candidate.trim();
            if ("*".equals(trimmed)) {
                return true;
            }
            if (trimmed.startsWith("W/")) {
                trimmed = trimmed.substring(2).trim();
            }
            if (trimmed.length() > 1 && trimmed.startsWith("\"") && trimmed.endsWith("\"")) {
                trimmed = trimmed.substring(1, trimmed.length() - 1);
            }
            if (entityTag.equals(trimmed)) {
                return true;
            }
        }
        return false;
    }
}
