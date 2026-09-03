package com.ebremer.lws.authn.rdf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** P2-2/3/4. A controlled identifier document is a resource other people fetch and cache. */
class RdfContentNegotiationTest {

    /**
     * The bug this replaces: negotiation was a substring test in a fixed order, so a client that
     * clearly preferred JSON-LD was handed its least-wanted syntax instead.
     */
    @Test
    void honoursQualityValues() {
        assertEquals(RdfContentNegotiation.JSON_LD,
                RdfContentNegotiation.best("application/ld+json;q=1.0, text/turtle;q=0.1"));
        assertEquals(RdfContentNegotiation.TURTLE,
                RdfContentNegotiation.best("application/ld+json;q=0.1, text/turtle;q=1.0"));
        assertEquals(RdfContentNegotiation.RDF_XML,
                RdfContentNegotiation.best("text/turtle;q=0.2, application/rdf+xml;q=0.9"));
    }

    /** The verifiers' own Accept header, which asks for Turtle first. */
    @Test
    void honoursTheVerifierPreferenceOrder() {
        assertEquals(RdfContentNegotiation.TURTLE, RdfContentNegotiation.best(
                "text/turtle, application/ld+json;q=0.9, application/n-triples;q=0.8, application/rdf+xml;q=0.7"));
    }

    @Test
    void handlesWildcardsAndAbsentHeaders() {
        assertEquals(RdfContentNegotiation.JSON_LD, RdfContentNegotiation.best("*/*"));
        assertEquals(RdfContentNegotiation.JSON_LD, RdfContentNegotiation.best(null));
        assertEquals(RdfContentNegotiation.JSON_LD, RdfContentNegotiation.best(""));
        assertEquals(RdfContentNegotiation.TURTLE, RdfContentNegotiation.best("text/*"));
    }

    /** A more specific match wins over a wildcard regardless of order (RFC 9110 §12.5.1). */
    @Test
    void specificityBeatsPosition() {
        assertEquals(RdfContentNegotiation.TURTLE, RdfContentNegotiation.best("*/*;q=0.1, text/turtle;q=0.8"));
        assertEquals(RdfContentNegotiation.TURTLE, RdfContentNegotiation.best("text/turtle;q=0.8, */*;q=0.1"));
    }

    /** An Accept naming nothing on offer used to be answered with JSON-LD anyway. */
    @Test
    void returnsNothingWhenNoSupportedTypeIsAcceptable() {
        assertNull(RdfContentNegotiation.best("text/html"));
        assertNull(RdfContentNegotiation.best("application/pdf, image/png"));
    }

    /** q=0 means "not acceptable", including when it disables a wildcard match. */
    @Test
    void respectsQualityZero() {
        assertNull(RdfContentNegotiation.best("*/*;q=0"));
        assertEquals(RdfContentNegotiation.TURTLE,
                RdfContentNegotiation.best("application/ld+json;q=0, text/turtle"));
    }

    @Test
    void survivesMalformedHeaders() {
        assertNull(RdfContentNegotiation.best("garbage"));
        assertEquals(RdfContentNegotiation.TURTLE, RdfContentNegotiation.best("text/turtle;q=notanumber, text/turtle"));
    }

    // ------------------------------------------------------------------------------ cache headers

    @Test
    void entityTagsDistinguishRepresentations() {
        String turtle = "<a> <b> <c> .";
        String jsonLd = "{\"id\":\"a\"}";
        assertEquals(RdfContentNegotiation.entityTag(turtle), RdfContentNegotiation.entityTag(turtle));
        assertNotEquals(RdfContentNegotiation.entityTag(turtle), RdfContentNegotiation.entityTag(jsonLd),
                "two syntaxes of one document are different representations and need different tags");
        assertFalse(RdfContentNegotiation.entityTag(turtle).startsWith("\""),
                "the value is bare; JAX-RS adds the quotes, and quoting twice matches nothing");
    }

    @Test
    void matchesIfNoneMatch() {
        String tag = RdfContentNegotiation.entityTag("body");
        String onTheWire = "\"" + tag + "\"";   // what a client echoes back
        assertTrue(RdfContentNegotiation.matches(onTheWire, tag));
        assertTrue(RdfContentNegotiation.matches("\"other\", " + onTheWire, tag));
        assertTrue(RdfContentNegotiation.matches("*", tag));
        assertTrue(RdfContentNegotiation.matches("W/" + onTheWire, tag), "a weak validator still matches");
        assertFalse(RdfContentNegotiation.matches("\"other\"", tag));
        assertFalse(RdfContentNegotiation.matches(null, tag));
    }
}
