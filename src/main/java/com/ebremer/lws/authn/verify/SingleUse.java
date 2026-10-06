/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.verify;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.SingleUseObjectProvider;

/**
 * Holds a credential to one use, for a caller that asks (R-34).
 *
 * <p><strong>Off unless the caller asks, deliberately.</strong> A {@code …/verify} endpoint is a
 * verification utility, not the point at which a credential is consumed: an LWS storage server
 * validates the <em>same</em> bearer token on every request it carries. Refusing the second look at a
 * token would break that outright. A caller that treats one verification as one use — a single-use
 * exchange, say — passes {@code single_use=true}, and a credential it has had verified that way once is
 * refused the next time any caller asks the same.</p>
 *
 * <p>The record is Keycloak's single-use object store — the one its action tokens use — so it is shared
 * by every node of a cluster and survives nothing it should not. Each credential is remembered by its
 * issuer and {@code jti} together, because a {@code jti} is only unique per issuer, until it expires:
 * its {@code exp}, plus the clock skew a verifier allows. The earlier, never-enabled in-memory cache
 * forgot after a fixed window whatever the {@code exp}, so a credential outliving the window could be
 * used again; and it was per node, and a flood of identifiers could evict a real one.</p>
 *
 * <p>Two credentials cannot be held to one use, and are refused when it is asked: one with no
 * {@code jti}, which there is nothing to remember by; and one still valid for more than
 * {@link #MAX_LIFESPAN_SECONDS}, which would have to be remembered for longer than this provider will
 * hold an entry — a single-use credential is a short-lived one.</p>
 *
 * @author Erich Bremer
 */
public final class SingleUse {

    /** The longest a credential may remain valid and still be held to one use: a day. */
    public static final long MAX_LIFESPAN_SECONDS = 24 * 60 * 60;

    /** Where uses are recorded. */
    @FunctionalInterface
    public interface Store {
        /** Records {@code key} for {@code lifespanSeconds}; {@code true} iff it was not already recorded. */
        boolean putIfAbsent(String key, long lifespanSeconds);
    }

    /** What became of a request to use a credential. */
    public enum Outcome {
        /** Not seen before, and now recorded. */
        FIRST_USE,
        /** Already used. */
        REPLAYED,
        /** No {@code jti} to remember it by. */
        NO_JTI,
        /** Valid for longer than {@link #MAX_LIFESPAN_SECONDS}. */
        TOO_LONG_LIVED
    }

    private final Store store;

    public SingleUse(Store store) {
        this.store = store;
    }

    /** Uses recorded in {@code session}'s single-use object store, shared across the cluster. */
    public static SingleUse of(KeycloakSession session) {
        SingleUseObjectProvider objects = session.singleUseObjects();
        return new SingleUse(objects::putIfAbsent);
    }

    /**
     * Uses the credential {@code issuer} identified by {@code jti}, which expires at {@code exp}.
     *
     * @param nowSeconds  the current time, in seconds since the epoch
     * @param skewSeconds the clock skew a verifier allows past {@code exp}
     */
    public Outcome use(String issuer, String jti, long exp, long nowSeconds, long skewSeconds) {
        if (jti == null || jti.isBlank()) {
            return Outcome.NO_JTI;
        }
        long lifespan = Math.max(1, exp + skewSeconds - nowSeconds);
        if (lifespan > MAX_LIFESPAN_SECONDS) {
            return Outcome.TOO_LONG_LIVED;
        }
        return store.putIfAbsent(key(issuer, jti), lifespan) ? Outcome.FIRST_USE : Outcome.REPLAYED;
    }

    /** A fixed-length key for the pair: the store need not hold arbitrary-length strings. */
    static String key(String issuer, String jti) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(((issuer == null ? "" : issuer) + '\0' + jti).getBytes(StandardCharsets.UTF_8));
            return "lws-authn-jti:" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
