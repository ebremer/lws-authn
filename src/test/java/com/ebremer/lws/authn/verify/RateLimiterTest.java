/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.verify;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * P0-3. The verify endpoints turn one small POST into outbound fetches and signature checks, so a
 * caller has to be held to a rate.
 */
class RateLimiterTest {

    @Test
    void allowsABurstThenRefusesUntilRefilled() {
        RateLimiter limiter = new RateLimiter(60);
        long t0 = 1_000_000L;
        for (int i = 0; i < 60; i++) {
            assertTrue(limiter.tryAcquire("10.0.0.1", t0), "permit " + i + " should be granted from a full bucket");
        }
        assertFalse(limiter.tryAcquire("10.0.0.1", t0), "the 61st request in the same instant must be refused");

        // 60/minute refills one permit per second.
        assertTrue(limiter.tryAcquire("10.0.0.1", t0 + 1_000), "a permit should be back after a second");
        assertFalse(limiter.tryAcquire("10.0.0.1", t0 + 1_000), "but only one");
    }

    @Test
    void callersAreLimitedIndependently() {
        RateLimiter limiter = new RateLimiter(1);
        long t0 = 1_000_000L;
        assertTrue(limiter.tryAcquire("10.0.0.1", t0));
        assertFalse(limiter.tryAcquire("10.0.0.1", t0));
        assertTrue(limiter.tryAcquire("10.0.0.2", t0), "one caller must not exhaust another caller's budget");
    }

    @Test
    void neverGrowsWithoutBound() {
        RateLimiter limiter = new RateLimiter(1);
        long t0 = 1_000_000L;
        // Far more distinct callers than the cap: the limiter must not become the memory-exhaustion
        // vector it exists to prevent.
        for (int i = 0; i < RateLimiter.MAX_TRACKED_CALLERS * 2; i++) {
            limiter.tryAcquire("10.1." + (i / 256) + "." + (i % 256), t0);
        }
        assertTrue(limiter.tryAcquire("10.9.9.9", t0), "eviction must keep the limiter working");
    }

    @Test
    void rejectsANonsenseRate() {
        assertThrows(IllegalArgumentException.class, () -> new RateLimiter(0));
        assertThrows(IllegalArgumentException.class, () -> new RateLimiter(-5));
    }
}
