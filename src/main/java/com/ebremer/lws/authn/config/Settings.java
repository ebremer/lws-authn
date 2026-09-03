/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * The one place a configurable value is looked up, so every setting in this provider is set the same
 * three ways.
 */
package com.ebremer.lws.authn.config;

import org.keycloak.Config;

/**
 * Resolves a setting from the provider's {@link Config.Scope}, then a system property, then an
 * environment variable, then a compiled-in default.
 *
 * <p>All three sources exist because a Keycloak extension is configured in three different situations.
 * {@code Config.Scope} is the supported surface — {@code kc.sh build --spi-realm-restapi-extension--
 * <provider>--<key>=<value>} — and is the only one that can differ per provider. A system property
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

    /** As {@link #get}, parsed as a {@code long}; a value that will not parse falls back with no fuss. */
    public static long getLong(Config.Scope scope, String key, String systemProperty,
                               String environmentVariable, long fallback) {
        String value = get(scope, key, systemProperty, environmentVariable, null);
        if (value == null) {
            return fallback;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    /** As {@link #getLong}, narrowed to {@code int}. */
    public static int getInt(Config.Scope scope, String key, String systemProperty,
                             String environmentVariable, int fallback) {
        long value = getLong(scope, key, systemProperty, environmentVariable, fallback);
        return value < Integer.MIN_VALUE || value > Integer.MAX_VALUE ? fallback : (int) value;
    }

    /** As {@link #get}, read as a boolean; anything other than {@code true}/{@code false} falls back. */
    public static boolean getBoolean(Config.Scope scope, String key, String systemProperty,
                                     String environmentVariable, boolean fallback) {
        String value = get(scope, key, systemProperty, environmentVariable, null);
        if (value == null) {
            return fallback;
        }
        String trimmed = value.trim();
        if (trimmed.equalsIgnoreCase("true")) {
            return true;
        }
        if (trimmed.equalsIgnoreCase("false")) {
            return false;
        }
        return fallback;
    }
}
