/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.verify;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A bounded, in-memory token bucket per caller.
 *
 * <p>Credential verification is expensive out of proportion to the request that triggers it: the
 * OpenID and self-signed-CID verifiers each make up to three outbound fetches, and the SAML verifier
 * parses XML and checks an RSA signature. Without a ceiling, one client can turn a single POST into
 * seconds of this server's time and three requests to a target of its choosing.</p>
 *
 * <p>The bucket refills continuously at {@code permitsPerMinute / 60} per second and holds at most
 * {@code permitsPerMinute} tokens, so a caller may burst up to a minute's worth and then settles to the
 * steady rate. Callers are tracked in an access-ordered map capped at {@link #MAX_TRACKED_CALLERS}
 * entries, so the limiter cannot itself become a memory-exhaustion vector.</p>
 *
 * <p>Time is {@link System#nanoTime()}, not the wall clock (R-36): with the wall clock, a step backwards
 * — an NTP correction, a VM resumed — left an empty bucket empty until the clock caught up again, and
 * the caller refused for that long.</p>
 *
 * @author Erich Bremer
 */
public final class RateLimiter {

    /** Upper bound on distinct callers tracked at once; the least recently seen is evicted. */
    public static final int MAX_TRACKED_CALLERS = 4096;

    private final int permitsPerMinute;
    private final Map<String, Bucket> buckets = new LinkedHashMap<>(64, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Bucket> eldest) {
            return size() > MAX_TRACKED_CALLERS;
        }
    };

    private static final class Bucket {
        private double tokens;
        private long lastRefillMillis;
    }

    public RateLimiter(int permitsPerMinute) {
        if (permitsPerMinute <= 0) {
            throw new IllegalArgumentException("permitsPerMinute must be positive");
        }
        this.permitsPerMinute = permitsPerMinute;
    }

    public int getPermitsPerMinute() {
        return permitsPerMinute;
    }

    /** Takes one permit for {@code key}, or returns {@code false} when the caller is over its rate. */
    public boolean tryAcquire(String key) {
        return tryAcquire(key, monotonicMillis());
    }

    /**
     * Whole seconds until {@code key} has a permit again — at least 1 — for a {@code Retry-After}
     * header (R-36).
     */
    public long retryAfterSeconds(String key) {
        return retryAfterSeconds(key, monotonicMillis());
    }

    /** As {@link #retryAfterSeconds(String)}, with an explicit clock (for tests). */
    synchronized long retryAfterSeconds(String key, long nowMillis) {
        Bucket bucket = buckets.get(key);
        if (bucket == null) {
            return 1;
        }
        double tokens = Math.min(permitsPerMinute,
                bucket.tokens + Math.max(0, nowMillis - bucket.lastRefillMillis) * permitsPerMinute / 60_000.0d);
        double missing = Math.max(0, 1.0d - tokens);
        // Less a hair, so floating-point dust on an exact second does not round it up to the next one.
        return Math.max(1, (long) Math.ceil(missing * 60.0d / permitsPerMinute - 1e-9));
    }

    private static long monotonicMillis() {
        return System.nanoTime() / 1_000_000L;
    }

    /** As {@link #tryAcquire(String)}, with an explicit clock (for tests). */
    synchronized boolean tryAcquire(String key, long nowMillis) {
        Bucket bucket = buckets.get(key);
        if (bucket == null) {
            bucket = new Bucket();
            bucket.tokens = permitsPerMinute;
            bucket.lastRefillMillis = nowMillis;
            buckets.put(key, bucket);
        } else {
            double refill = (nowMillis - bucket.lastRefillMillis) * permitsPerMinute / 60_000.0d;
            if (refill > 0) {
                bucket.tokens = Math.min(permitsPerMinute, bucket.tokens + refill);
                bucket.lastRefillMillis = nowMillis;
            }
        }
        if (bucket.tokens < 1.0d) {
            return false;
        }
        bucket.tokens -= 1.0d;
        return true;
    }
}
