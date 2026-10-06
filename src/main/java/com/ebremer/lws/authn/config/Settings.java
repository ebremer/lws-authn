/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * The one place a configurable value is looked up, so every setting in this provider is set the same
 * three ways.
 */
package com.ebremer.lws.authn.config;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.jboss.logging.Logger;
import org.keycloak.Config;

/**
 * Resolves a setting from the provider's {@link Config.Scope}, then a system property, then an
 * environment variable, then a compiled-in default.
 *
 * <p>All three sources exist because a Keycloak extension is configured in three different situations.
 * {@code Config.Scope} is the supported surface — {@code spi-realm-restapi-extension--<provider>--<key>}
 * in {@code keycloak.conf} or on {@code kc.sh start}, never on {@code kc.sh build}, which drops runtime
 * options (R-12) — and is the only one that can differ per provider. A system property
 * suits a test or a one-off {@code kc.sh start -D…}. An environment variable is what a container
 * deployment can set without rebuilding the image, which is how this provider was configured before it
 * read its scope at all; keeping it means an existing deployment's settings still apply.</p>
 *
 * @author Erich Bremer
 */
public final class Settings {

    private Settings() {
    }

    /**
     * The first non-blank of: {@code scope[key]}, {@code System.getProperty(systemProperty)},
     * {@code System.getenv(environmentVariable)}, {@code fallback}.
     *
     * @param scope the provider's configuration scope, or {@code null} when the factory was not given one
     */
    public static String get(Config.Scope scope, String key, String systemProperty,
                             String environmentVariable, String fallback) {
        if (scope != null) {
            String value = scope.get(key);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        String value = System.getProperty(systemProperty);
        if (value == null || value.isBlank()) {
            value = System.getenv(environmentVariable);
        }
        return value == null || value.isBlank() ? fallback : value;
    }

    /**
     * Whether any of the three sources sets {@code key} at all. Used where "not configured" has to be
     * told apart from "configured to the default value" — a server-wide setting several providers
     * could each contribute is only overwritten by a provider that actually names it.
     */
    public static boolean isSet(Config.Scope scope, String key, String systemProperty,
                                String environmentVariable) {
        return get(scope, key, systemProperty, environmentVariable, null) != null;
    }

    /**
     * As {@link #get}, parsed as a non-negative {@code long} in {@code [min, max]} (R-35). A value outside
     * the range is clamped to it; one that will not parse, or is negative — every number this provider
     * reads is a count, a size or a duration — falls back. Either way the log says so: a mistyped
     * setting used to become the default without a word, and {@code rate-limit=-1} turned limiting off.
     */
    public static long getLong(Config.Scope scope, String key, String systemProperty,
                               String environmentVariable, long fallback, long min, long max) {
        return parseLong(key, get(scope, key, systemProperty, environmentVariable, null), fallback, min, max);
    }

    /** As {@link #getLong(Config.Scope, String, String, String, long, long, long)}, narrowed to {@code int}. */
    public static int getInt(Config.Scope scope, String key, String systemProperty,
                             String environmentVariable, int fallback, int min, int max) {
        return (int) getLong(scope, key, systemProperty, environmentVariable, fallback, min, max);
    }

    /** As {@link #get}, read as a boolean; anything other than {@code true}/{@code false} falls back, and is logged. */
    public static boolean getBoolean(Config.Scope scope, String key, String systemProperty,
                                     String environmentVariable, boolean fallback) {
        return parseBoolean(key, get(scope, key, systemProperty, environmentVariable, null), fallback);
    }

    /** {@code raw} as {@link #getLong(Config.Scope, String, String, String, long, long, long)} reads it. */
    static long parseLong(String key, String raw, long fallback, long min, long max) {
        if (raw == null) {
            return fallback;
        }
        long value;
        try {
            value = Long.parseLong(raw.trim());
        } catch (NumberFormatException unreadable) {
            warnOnce(key, raw, "is not a whole number; using " + fallback);
            return fallback;
        }
        if (value < 0) {
            warnOnce(key, raw, "is negative; using " + fallback);
            return fallback;
        }
        if (value < min || value > max) {
            long clamped = Math.max(min, Math.min(max, value));
            warnOnce(key, raw, "is outside " + min + "–" + max + "; using " + clamped);
            return clamped;
        }
        return value;
    }

    /** {@code raw} as {@link #getBoolean} reads it. */
    static boolean parseBoolean(String key, String raw, boolean fallback) {
        if (raw == null) {
            return fallback;
        }
        String trimmed = raw.trim();
        if (trimmed.equalsIgnoreCase("true")) {
            return true;
        }
        if (trimmed.equalsIgnoreCase("false")) {
            return false;
        }
        warnOnce(key, raw, "is neither true nor false; using " + fallback);
        return fallback;
    }

    private static final Logger log = Logger.getLogger(Settings.class);

    /** What has been warned about, so a setting several providers read is complained of once. */
    private static final Set<String> WARNED = ConcurrentHashMap.newKeySet();

    /** Logs that {@code key}'s value {@code raw} {@code problem}, once per key and value. */
    public static void warnOnce(String key, String raw, String problem) {
        if (WARNED.add(key + "=" + raw)) {
            log.warnf("lws-authn setting '%s' has the value '%s', which %s", key, raw, problem);
        }
    }
}
