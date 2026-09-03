/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Per-provider configuration: the settings one suite's endpoints may differ on.
 */
package com.ebremer.lws.authn.config;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.RealmModel;

import com.ebremer.lws.authn.verify.RateLimiter;
import com.ebremer.lws.authn.verify.VerifyAccess;

/**
 * The configuration of one suite's endpoints, read once by its factory from its own
 * {@link Config.Scope}.
 *
 * <p>Held on the factory because {@code Config.Scope} is only offered there, and read eagerly so a
 * misconfiguration is logged at startup rather than once per request.</p>
 *
 * <table>
 *   <caption>Settings (scope keys are per provider id: {@code lws}, {@code lws-ssi-cid},
 *            {@code lws-saml}, {@code lws-ssi-did-key})</caption>
 *   <tr><th>Scope key</th><th>System property</th><th>Environment</th><th>Default</th></tr>
 *   <tr><td>{@code enabled}</td><td>{@code lws.authn.enabled}</td><td>{@code LWS_AUTHN_ENABLED}</td><td>{@code true}</td></tr>
 *   <tr><td>{@code audience}</td><td>{@code lws.authn.audience}</td><td>{@code LWS_AUTHN_AUDIENCE}</td><td>none</td></tr>
 *   <tr><td>{@code cid-cache-seconds}</td><td>{@code lws.authn.cid.cacheSeconds}</td><td>{@code LWS_AUTHN_CID_CACHE_SECONDS}</td><td>{@code 300}</td></tr>
 *   <tr><td>{@code cid-rate-limit}</td><td>{@code lws.authn.cid.rateLimit}</td><td>{@code LWS_AUTHN_CID_RATE_LIMIT}</td><td>{@code 600}</td></tr>
 * </table>
 *
 * <p>{@code enabled} additionally honours a per-realm override, which is the only one of these that
 * can sensibly differ between realms of the same server: a realm attribute named
 * {@code lws.authn.<providerId>.enabled} (for example {@code lws.authn.lws-saml.enabled}) set to
 * {@code false} turns that suite off for that realm alone. See {@link #isEnabled(RealmModel)}.</p>
 *
 * @author Erich Bremer
 */
public final class EndpointSettings {

    private static final Logger log = Logger.getLogger(EndpointSettings.class);

    /** How long a controlled identifier document may be cached, in seconds. */
    public static final long DEFAULT_CID_CACHE_SECONDS = 300;

    /**
     * Requests per minute, per caller, allowed against a {@code cid/{userId}} endpoint.
     *
     * <p>An order of magnitude above the verify limit: serving a controlled identifier document is a
     * cheap local read that every verifier in the world is entitled to make, so the ceiling is there
     * to bound enumeration of the realm's user ids, not to ration normal use.</p>
     */
    public static final int DEFAULT_CID_RATE_LIMIT = 600;

    private final String providerId;
    private final boolean enabled;
    private final String defaultAudience;
    private final long cidCacheSeconds;
    private final VerifyAccess verifyAccess;
    private final RateLimiter cidLimiter;

    private EndpointSettings(String providerId, boolean enabled, String defaultAudience,
                             long cidCacheSeconds, int cidRateLimit, VerifyAccess verifyAccess) {
        this.providerId = providerId;
        this.enabled = enabled;
        this.defaultAudience = defaultAudience;
        this.cidCacheSeconds = cidCacheSeconds;
        this.verifyAccess = verifyAccess;
        this.cidLimiter = cidRateLimit > 0 ? new RateLimiter(cidRateLimit) : null;
    }

    /**
     * Reads a provider's settings, and contributes whatever its scope says about the server-wide ones.
     *
     * @param scope may be {@code null} (the factory was not given one), in which case only the
     *              system-property and environment fallbacks apply
     */
    public static EndpointSettings from(String providerId, Config.Scope scope) {
        ServerSettings.contribute(providerId, scope);
        return read(providerId, scope);
    }

    /**
     * The settings that apply when nothing is configured.
     *
     * <p>Deliberately does <em>not</em> contribute to {@link ServerSettings}: a factory holds one of
     * these from the moment it is constructed, before Keycloak offers it a scope, and a placeholder
     * built from the environment alone must not count as a provider's opinion — the real
     * {@link #from} that follows would then look like a second provider disagreeing with the first.</p>
     */
    public static EndpointSettings defaults(String providerId) {
        return read(providerId, null);
    }

    private static EndpointSettings read(String providerId, Config.Scope scope) {
        boolean enabled = Settings.getBoolean(scope, "enabled", "lws.authn.enabled", "LWS_AUTHN_ENABLED", true);
        if (!enabled) {
            log.infof("lws-authn provider '%s' is disabled by configuration; its endpoints will answer 404",
                    providerId);
        }
        String audience = Settings.get(scope, "audience", "lws.authn.audience", "LWS_AUTHN_AUDIENCE", null);
        long cache = Math.max(0, Settings.getLong(scope, "cid-cache-seconds",
                "lws.authn.cid.cacheSeconds", "LWS_AUTHN_CID_CACHE_SECONDS", DEFAULT_CID_CACHE_SECONDS));
        int cidRateLimit = Math.max(0, Settings.getInt(scope, "cid-rate-limit",
                "lws.authn.cid.rateLimit", "LWS_AUTHN_CID_RATE_LIMIT", DEFAULT_CID_RATE_LIMIT));
        return new EndpointSettings(providerId, enabled, blankToNull(audience), cache, cidRateLimit,
                VerifyAccess.from(scope));
    }

    /** The provider id these settings belong to ({@code lws}, {@code lws-saml}, ...). */
    public String getProviderId() {
        return providerId;
    }

    /**
     * Whether this suite's endpoints are served for {@code realm}.
     *
     * <p>A realm attribute {@code lws.authn.<providerId>.enabled} overrides the provider-wide flag, so
     * a server hosting several realms can offer a suite to one and not another. An attribute that is
     * neither {@code true} nor {@code false} is ignored rather than guessed at.</p>
     */
    public boolean isEnabled(RealmModel realm) {
        if (realm != null) {
            String attribute = realm.getAttribute("lws.authn." + providerId + ".enabled");
            if (attribute != null) {
                if (attribute.trim().equalsIgnoreCase("true")) {
                    return true;
                }
                if (attribute.trim().equalsIgnoreCase("false")) {
                    return false;
                }
            }
        }
        return enabled;
    }

    /**
     * An audience every credential this suite verifies must be restricted to, used when the request
     * does not name one of its own. Lets a deployment enforce the binding once instead of trusting
     * every caller to pass {@code audience} — the parameter is optional, and a caller that forgets it
     * accepts a credential minted for somewhere else.
     *
     * @return the configured audience, or {@code null} when there is none
     */
    public String getDefaultAudience() {
        return defaultAudience;
    }

    /** The audience to enforce for a request that supplied {@code requested} (possibly {@code null}). */
    public String audienceFor(String requested) {
        return requested == null || requested.isBlank() ? defaultAudience : requested;
    }

    /** {@code Cache-Control: max-age} for a served controlled identifier document, in seconds. */
    public long getCidCacheSeconds() {
        return cidCacheSeconds;
    }

    /** The access policy for this suite's {@code verify} endpoint. */
    public VerifyAccess getVerifyAccess() {
        return verifyAccess;
    }

    /** The rate limiter for this suite's {@code cid/{userId}} endpoint, or {@code null} when off. */
    public RateLimiter getCidLimiter() {
        return cidLimiter;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
