package com.ebremer.lws.authn.verify;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** P2-8. Opt-in replay detection; see {@link ReplayCache} for why it is not on by default. */
class ReplayCacheTest {

    @Test
    void remembersAJtiWithinItsWindow() {
        ReplayCache cache = new ReplayCache(300);
        long t0 = 1_000_000L;
        assertTrue(cache.firstSighting("https://a.example", "jti-1", t0));
        assertFalse(cache.firstSighting("https://a.example", "jti-1", t0), "the second sighting is a replay");
        assertFalse(cache.firstSighting("https://a.example", "jti-1", t0 + 299_000L));
    }

    @Test
    void forgetsAfterTheWindow() {
        ReplayCache cache = new ReplayCache(300);
        long t0 = 1_000_000L;
        assertTrue(cache.firstSighting("https://a.example", "jti-1", t0));
        assertTrue(cache.firstSighting("https://a.example", "jti-1", t0 + 300_001L),
                "past the window there is nothing left to replay: exp is what bounds the credential");
    }

    /** jti is only required to be unique per issuer, so the key has to include the issuer. */
    @Test
    void identifiersAreScopedToTheirIssuer() {
        ReplayCache cache = new ReplayCache(300);
        long t0 = 1_000_000L;
        assertTrue(cache.firstSighting("https://a.example", "shared-jti", t0));
        assertTrue(cache.firstSighting("https://b.example", "shared-jti", t0),
                "two issuers may legitimately mint the same jti");
    }

    /** A credential with no jti cannot be tracked; the caller decides whether that is acceptable. */
    @Test
    void saysNothingAboutACredentialWithNoJti() {
        ReplayCache cache = new ReplayCache(300);
        long t0 = 1_000_000L;
        assertTrue(cache.firstSighting("https://a.example", null, t0));
        assertTrue(cache.firstSighting("https://a.example", null, t0));
        assertTrue(cache.firstSighting("https://a.example", "  ", t0));
    }

    @Test
    void isBounded() {
        ReplayCache cache = new ReplayCache(300);
        long t0 = 1_000_000L;
        for (int i = 0; i < ReplayCache.MAX_ENTRIES * 2; i++) {
            cache.firstSighting("https://a.example", "jti-" + i, t0);
        }
        assertTrue(cache.firstSighting("https://a.example", "fresh", t0), "eviction keeps it working");
    }

    @Test
    void rejectsANonsenseWindow() {
        assertThrows(IllegalArgumentException.class, () -> new ReplayCache(0));
        assertThrows(IllegalArgumentException.class, () -> new ReplayCache(-1));
    }
}
