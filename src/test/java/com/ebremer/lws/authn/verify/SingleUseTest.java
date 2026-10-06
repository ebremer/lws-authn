/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** R-34. A credential held to one use; see {@link SingleUse} for why only when a caller asks. */
class SingleUseTest {

    private static final long NOW = 1_900_000_000L;

    private final Map<String, Long> recorded = new HashMap<>();
    private final SingleUse uses = new SingleUse((key, lifespan) -> recorded.putIfAbsent(key, lifespan) == null);

    @Test
    void theSecondUseIsAReplay() {
        assertEquals(SingleUse.Outcome.FIRST_USE, uses.use("https://a.example", "jti-1", NOW + 300, NOW, 60));
        assertEquals(SingleUse.Outcome.REPLAYED, uses.use("https://a.example", "jti-1", NOW + 300, NOW + 10, 60));
    }

    /**
     * Remembered until the credential expires, skew included: the cache this replaces forgot after a
     * fixed window, so a credential that outlived it could be used again.
     */
    @Test
    void aUseIsRememberedUntilTheCredentialExpires() {
        uses.use("https://a.example", "jti-1", NOW + 300, NOW, 60);
        assertEquals(360L, recorded.values().iterator().next());
        uses.use("https://a.example", "jti-2", NOW - 30, NOW, 60);
        assertEquals(30L, recorded.get(SingleUse.key("https://a.example", "jti-2")));
    }

    /** jti is only required to be unique per issuer, so the key has to include the issuer. */
    @Test
    void identifiersAreScopedToTheirIssuer() {
        assertEquals(SingleUse.Outcome.FIRST_USE, uses.use("https://a.example", "shared", NOW + 300, NOW, 60));
        assertEquals(SingleUse.Outcome.FIRST_USE, uses.use("https://b.example", "shared", NOW + 300, NOW, 60));
        assertNotEquals(SingleUse.key("https://a.examp", "leshared"), SingleUse.key("https://a.example", "shared"));
    }

    @Test
    void whatCannotBeHeldToOneUseIsSaid() {
        assertEquals(SingleUse.Outcome.NO_JTI, uses.use("https://a.example", null, NOW + 300, NOW, 60));
        assertEquals(SingleUse.Outcome.NO_JTI, uses.use("https://a.example", " ", NOW + 300, NOW, 60));
        assertEquals(SingleUse.Outcome.TOO_LONG_LIVED,
                uses.use("https://a.example", "jti-1", NOW + SingleUse.MAX_LIFESPAN_SECONDS, NOW, 60));
        assertEquals(SingleUse.Outcome.FIRST_USE,
                uses.use("https://a.example", "jti-1", NOW + SingleUse.MAX_LIFESPAN_SECONDS - 60, NOW, 60));
        assertTrue(recorded.size() == 1);
    }

    /** The store holds a fixed-length key, whatever the issuer and jti. */
    @Test
    void keysAreOfFixedLength() {
        assertEquals(SingleUse.key("i", "j").length(), SingleUse.key("i".repeat(5000), "j".repeat(5000)).length());
    }
}
