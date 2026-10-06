/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * The server-wide tunables: the ones consumed by static utility code (the SSRF guard, the outbound
 * HTTP policy, the JWT validity window) rather than by a particular endpoint.
 */
package com.ebremer.lws.authn.config;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.jboss.logging.Logger;
import org.keycloak.Config;

import com.ebremer.lws.authn.net.SsrfGuard;

/**
 * Settings that apply to the whole extension rather than to one endpoint.
 *
 * <p>These are read by code with no request and no provider in hand — {@code SsrfGuard} inside a DNS
 * resolver, {@code OutboundHttp} when it builds its client, {@code JwsChecks} in a static predicate —
 * so they cannot be passed down from a factory the way a per-provider setting is. They live here
 * instead, in a holder each factory <em>contributes</em> to from its own {@link Config.Scope} at
 * {@code init} time, before any request is served.</p>
 *
 * <p>Contribution rather than assignment: three factories are initialised, each with its own scope, and
 * a value that is server-wide belongs to whichever of them actually names it. A factory whose scope
 * says nothing about a setting leaves it as it was, so configuring {@code allowed-internal-hosts} on
 * the {@code lws} provider alone still configures it for all three. When two providers set the same
 * server-wide value to different things the last one initialised wins, and says so in the log — there
 * is only one outbound HTTP client to configure.</p>
 *
 * <p>Any provider's scope comes before the system property and environment variable (R-35). Each
 * contribution records only what its scope says, and every setting is then worked out afresh from all
 * the scopes heard so far, falling back to the property, the variable and the default only when none
 * of them names it. A provider initialised later, with nothing in its scope, used to read the property
 * as its own opinion and overwrite another provider's scope value — so which won depended on the order
 * Keycloak happened to initialise them.</p>
 *
 * <table>
 *   <caption>Settings</caption>
 *   <tr><th>Scope key</th><th>System property</th><th>Environment</th><th>Default</th></tr>
 *   <tr><td>{@code allowed-internal-hosts}</td><td>{@code lws.authn.allowedInternalHosts}</td><td>{@code LWS_AUTHN_ALLOWED_INTERNAL_HOSTS}</td><td>none</td></tr>
 *   <tr><td>{@code http-timeout-millis}</td><td>{@code lws.authn.http.timeoutMillis}</td><td>{@code LWS_AUTHN_HTTP_TIMEOUT_MILLIS}</td><td>{@code 5000}</td></tr>
 *   <tr><td>{@code http-max-response-bytes}</td><td>{@code lws.authn.http.maxResponseBytes}</td><td>{@code LWS_AUTHN_HTTP_MAX_RESPONSE_BYTES}</td><td>{@code 262144}</td></tr>
 *   <tr><td>{@code http-deadline-millis}</td><td>{@code lws.authn.http.deadlineMillis}</td><td>{@code LWS_AUTHN_HTTP_DEADLINE_MILLIS}</td><td>{@code 10000}</td></tr>
 *   <tr><td>{@code http-max-concurrent-per-caller}</td><td>{@code lws.authn.http.maxConcurrentPerCaller}</td><td>{@code LWS_AUTHN_HTTP_MAX_CONCURRENT_PER_CALLER}</td><td>{@code 4}</td></tr>
 *   <tr><td>{@code clock-skew-seconds}</td><td>{@code lws.authn.clockSkewSeconds}</td><td>{@code LWS_AUTHN_CLOCK_SKEW_SECONDS}</td><td>{@code 60}</td></tr>
 *   <tr><td>{@code http-cache-seconds}</td><td>{@code lws.authn.http.cacheSeconds}</td><td>{@code LWS_AUTHN_HTTP_CACHE_SECONDS}</td><td>{@code 300}</td></tr>
 *   <tr><td>{@code max-credential-lifetime-seconds}</td><td>{@code lws.authn.maxCredentialLifetimeSeconds}</td><td>{@code LWS_AUTHN_MAX_CREDENTIAL_LIFETIME_SECONDS}</td><td>{@code 0} (no limit)</td></tr>
 *   <tr><td>{@code http-mode}</td><td>{@code lws.authn.http.mode}</td><td>{@code LWS_AUTHN_HTTP_MODE}</td><td>{@code guarded}</td></tr>
 * </table>
 *
 * @author Erich Bremer
 */
public final class ServerSettings {

    private static final Logger log = Logger.getLogger(ServerSettings.class);

    private ServerSettings() {
    }

    /** Connect / read / connection-request timeout applied to each outbound verifier fetch. */
    public static final int DEFAULT_HTTP_TIMEOUT_MILLIS = 5_000;

    /**
     * Maximum response body the verifiers will consume. Controlled identifier documents, OIDC
     * discovery documents and JWK sets are all small (a few KB); 256&nbsp;KiB is a generous ceiling
     * that still rejects a hostile target streaming an unbounded body.
     */
    public static final long DEFAULT_MAX_RESPONSE_BYTES = 256L * 1024L;

    /**
     * The whole of one outbound fetch — waiting for a connection, connecting, the TLS handshake and
     * reading the body — must finish within this, or it is aborted. The per-operation timeout alone
     * bounds each read, not their sum: a server that sends one byte just inside it, every time, holds
     * the connection for as long as it likes (R-01).
     */
    public static final int DEFAULT_HTTP_DEADLINE_MILLIS = 10_000;

    /**
     * Outbound fetches one caller may have in flight at once. The verifiers share one connection pool,
     * so without a per-caller bound a single caller pointing every request at a slow server could hold
     * all of it, and every other caller's verification would wait for a connection (R-01).
     */
    public static final int DEFAULT_HTTP_MAX_CONCURRENT_PER_CALLER = 4;

    /**
     * Leeway allowed on {@code exp}, {@code nbf} and the SAML {@code Conditions} window. Both JWT
     * suites say a verifier "MAY provide for some small leeway to account for clock skew".
     */
    public static final long DEFAULT_CLOCK_SKEW_SECONDS = 60;

    /** Upper bound on the configurable skew: past a few minutes it stops being clock skew. */
    private static final long MAX_CLOCK_SKEW_SECONDS = 600;

    /**
     * How long a fetched document — a controlled identifier document, a DID document, an OpenID
     * configuration or JWK set — may be reused, at most, in seconds; {@code 0} turns the cache off. A
     * document's own {@code Cache-Control} can shorten it or forbid caching, never lengthen it. Both JWT
     * suites encourage verifiers "to cache controlled identifier documents to reduce unnecessary network
     * requests and the associated metadata leakage" (R-26); five minutes is how long this provider tells
     * others to cache its own.
     */
    public static final long DEFAULT_HTTP_CACHE_SECONDS = 300;

    /**
     * The longest a JWT credential may be valid for — {@code exp} minus {@code iat} — or {@code 0} for no
     * limit, the default. Neither suite bounds a credential's lifetime, so a self-issued token with
     * {@code exp} in the year 9999 is valid until then; a deployment that wants stolen credentials to
     * age out can say how fast (R-28).
     */
    public static final long DEFAULT_MAX_CREDENTIAL_LIFETIME_SECONDS = 0;

    /** Upper bound on the configurable lifetime: ten years. */
    private static final long MAX_MAX_CREDENTIAL_LIFETIME_SECONDS = 10L * 365 * 24 * 3600;

    /** How outbound fetches are made: {@code guarded}, the default, or {@code session}. See {@link #httpMode()}. */
    public static final String DEFAULT_HTTP_MODE = "guarded";

    private static volatile Set<String> allowedInternalHosts;
    private static volatile int httpTimeoutMillis = DEFAULT_HTTP_TIMEOUT_MILLIS;
    private static volatile long maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES;
    private static volatile int httpDeadlineMillis = DEFAULT_HTTP_DEADLINE_MILLIS;
    private static volatile int httpMaxConcurrentPerCaller = DEFAULT_HTTP_MAX_CONCURRENT_PER_CALLER;
    private static volatile long clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS;
    private static volatile long maxCredentialLifetimeSeconds = DEFAULT_MAX_CREDENTIAL_LIFETIME_SECONDS;
    private static volatile long httpCacheSeconds = DEFAULT_HTTP_CACHE_SECONDS;
    private static volatile String httpMode = DEFAULT_HTTP_MODE;

    /** One server-wide setting's three names. */
    private record Key(String scopeKey, String systemProperty, String environmentVariable) {
    }

    private static final Key ALLOWED_INTERNAL_HOSTS =
            new Key("allowed-internal-hosts", "lws.authn.allowedInternalHosts", "LWS_AUTHN_ALLOWED_INTERNAL_HOSTS");
    private static final Key HTTP_TIMEOUT_MILLIS =
            new Key("http-timeout-millis", "lws.authn.http.timeoutMillis", "LWS_AUTHN_HTTP_TIMEOUT_MILLIS");
    private static final Key HTTP_MAX_RESPONSE_BYTES =
            new Key("http-max-response-bytes", "lws.authn.http.maxResponseBytes", "LWS_AUTHN_HTTP_MAX_RESPONSE_BYTES");
    private static final Key HTTP_DEADLINE_MILLIS =
            new Key("http-deadline-millis", "lws.authn.http.deadlineMillis", "LWS_AUTHN_HTTP_DEADLINE_MILLIS");
    private static final Key HTTP_MAX_CONCURRENT_PER_CALLER = new Key("http-max-concurrent-per-caller",
            "lws.authn.http.maxConcurrentPerCaller", "LWS_AUTHN_HTTP_MAX_CONCURRENT_PER_CALLER");
    private static final Key CLOCK_SKEW_SECONDS =
            new Key("clock-skew-seconds", "lws.authn.clockSkewSeconds", "LWS_AUTHN_CLOCK_SKEW_SECONDS");
    private static final Key HTTP_CACHE_SECONDS =
            new Key("http-cache-seconds", "lws.authn.http.cacheSeconds", "LWS_AUTHN_HTTP_CACHE_SECONDS");
    private static final Key MAX_CREDENTIAL_LIFETIME_SECONDS = new Key("max-credential-lifetime-seconds",
            "lws.authn.maxCredentialLifetimeSeconds", "LWS_AUTHN_MAX_CREDENTIAL_LIFETIME_SECONDS");
    private static final Key HTTP_MODE = new Key("http-mode", "lws.authn.http.mode", "LWS_AUTHN_HTTP_MODE");

    private static final List<Key> KEYS = List.of(ALLOWED_INTERNAL_HOSTS, HTTP_TIMEOUT_MILLIS,
            HTTP_MAX_RESPONSE_BYTES, HTTP_DEADLINE_MILLIS, HTTP_MAX_CONCURRENT_PER_CALLER, CLOCK_SKEW_SECONDS,
            HTTP_CACHE_SECONDS, MAX_CREDENTIAL_LIFETIME_SECONDS, HTTP_MODE);

    /** What the providers' scopes have said, by scope key: these come before any other source. */
    private static final Map<String, String> fromScopes = new LinkedHashMap<>();

    /**
     * Records whatever {@code scope} has to say about the server-wide settings, then works every one of
     * them out again. Called by every provider factory's {@code init}.
     *
     * @param providerId the contributing provider, named only in the log
     */
    public static synchronized void contribute(String providerId, Config.Scope scope) {
        for (Key key : KEYS) {
            String value = scope == null ? null : scope.get(key.scopeKey());
            if (value == null || value.isBlank()) {
                continue;
            }
            String previous = fromScopes.put(key.scopeKey(), value.trim());
            if (previous != null && !previous.equals(value.trim())) {
                log.warnf("lws-authn server-wide setting '%s' was already %s; provider '%s' is changing it to %s",
                        key.scopeKey(), previous, providerId, value.trim());
            }
        }
        apply();
    }

    /** The value in force for {@code key}: a provider's scope, else the property, the variable, or none. */
    private static String raw(Key key) {
        String value = fromScopes.get(key.scopeKey());
        return value != null ? value : Settings.get(null, key.scopeKey(), key.systemProperty(),
                key.environmentVariable(), null);
    }

    private static long number(Key key, long fallback, long min, long max) {
        return Settings.parseLong(key.scopeKey(), raw(key), fallback, min, max);
    }

    private static void apply() {
        // Left unresolved when nothing names it, so allowedInternalHosts() reads the property when asked.
        String hosts = raw(ALLOWED_INTERNAL_HOSTS);
        allowedInternalHosts = hosts == null ? null : parseHosts(hosts);
        httpTimeoutMillis = (int) number(HTTP_TIMEOUT_MILLIS, DEFAULT_HTTP_TIMEOUT_MILLIS, 100, 60_000);
        maxResponseBytes = number(HTTP_MAX_RESPONSE_BYTES, DEFAULT_MAX_RESPONSE_BYTES, 1024L, 16L * 1024L * 1024L);
        httpDeadlineMillis = (int) number(HTTP_DEADLINE_MILLIS, DEFAULT_HTTP_DEADLINE_MILLIS, 100, 120_000);
        httpMaxConcurrentPerCaller = (int) number(HTTP_MAX_CONCURRENT_PER_CALLER,
                DEFAULT_HTTP_MAX_CONCURRENT_PER_CALLER, 1, 64);
        clockSkewSeconds = number(CLOCK_SKEW_SECONDS, DEFAULT_CLOCK_SKEW_SECONDS, 0, MAX_CLOCK_SKEW_SECONDS);
        httpCacheSeconds = number(HTTP_CACHE_SECONDS, DEFAULT_HTTP_CACHE_SECONDS, 0, 86_400);
        maxCredentialLifetimeSeconds = number(MAX_CREDENTIAL_LIFETIME_SECONDS,
                DEFAULT_MAX_CREDENTIAL_LIFETIME_SECONDS, 0, MAX_MAX_CREDENTIAL_LIFETIME_SECONDS);
        httpMode = parseHttpMode(raw(HTTP_MODE));
    }

    private static String parseHttpMode(String value) {
        if (value == null) {
            return DEFAULT_HTTP_MODE;
        }
        String mode = value.trim().toLowerCase(Locale.ROOT);
        if (mode.equals("guarded") || mode.equals("session")) {
            return mode;
        }
        Settings.warnOnce(HTTP_MODE.scopeKey(), value, "is neither 'guarded' nor 'session'; using guarded");
        return DEFAULT_HTTP_MODE;
    }

    /**
     * The allow-list of internal host names the SSRF guard permits.
     *
     * <p>Resolved lazily the first time it is asked for, so the guard behaves the same in a unit test —
     * where no factory has been initialised and the test sets the system property itself — as it does
     * in a server. Once {@link #contribute} has supplied a value, that value stands.</p>
     */
    public static Set<String> allowedInternalHosts() {
        Set<String> configured = allowedInternalHosts;
        if (configured != null) {
            return configured;
        }
        return parseHosts(Settings.get(null, null, ALLOWED_INTERNAL_HOSTS.systemProperty(),
                ALLOWED_INTERNAL_HOSTS.environmentVariable(), null));
    }

    /** Connect / read / connection-request timeout for an outbound verifier fetch, in milliseconds. */
    public static int httpTimeoutMillis() {
        return httpTimeoutMillis;
    }

    /** Maximum response body a verifier fetch will consume, in bytes. */
    public static long maxResponseBytes() {
        return maxResponseBytes;
    }

    /** The total time one outbound verifier fetch may take before it is aborted, in milliseconds. */
    public static int httpDeadlineMillis() {
        return httpDeadlineMillis;
    }

    /** Outbound verifier fetches one caller may have in flight at once. */
    public static int httpMaxConcurrentPerCaller() {
        return httpMaxConcurrentPerCaller;
    }

    /** Leeway allowed on a credential's validity window, in seconds. */
    public static long clockSkewSeconds() {
        return clockSkewSeconds;
    }

    /** The longest a fetched document may be reused, in seconds; {@code 0} when nothing is cached. */
    public static long httpCacheSeconds() {
        return httpCacheSeconds;
    }

    /** The longest {@code exp − iat} a JWT credential may have, in seconds; {@code 0} for no limit. */
    public static long maxCredentialLifetimeSeconds() {
        return maxCredentialLifetimeSeconds;
    }

    /**
     * How outbound fetches are made. {@code guarded}, the default: through this provider's own client,
     * whose DNS resolver vets every address it connects to — rebinding-safe, but it does not use an HTTP
     * proxy. {@code session}: through Keycloak's server-wide client, which honours Keycloak's proxy
     * mappings, with the deadline, size cap and per-caller bound still applied but name resolution
     * Keycloak's, so it is not rebinding-safe. The only way out through an egress proxy (R-35).
     */
    public static String httpMode() {
        return httpMode;
    }

    /**
     * The server-wide settings in force, for the startup log (R-12). Keycloak drops a runtime option
     * given to {@code kc.sh build} with no more than a warning, so the settings an operator meant and
     * the settings in force can differ silently; this is how to tell.
     */
    public static String describe() {
        return "allowed-internal-hosts=" + allowedInternalHosts()
                + ", http-timeout-millis=" + httpTimeoutMillis
                + ", http-deadline-millis=" + httpDeadlineMillis
                + ", http-max-response-bytes=" + maxResponseBytes
                + ", http-max-concurrent-per-caller=" + httpMaxConcurrentPerCaller
                + ", http-cache-seconds=" + httpCacheSeconds
                + ", clock-skew-seconds=" + clockSkewSeconds
                + ", max-credential-lifetime-seconds="
                + (maxCredentialLifetimeSeconds == 0 ? "(no limit)" : maxCredentialLifetimeSeconds)
                + ", http-mode=" + httpMode;
    }

    /** Logs {@link #describe()} once per server start, however many providers ask. */
    public static void logOnce() {
        if (logged.compareAndSet(false, true)) {
            log.infof("lws-authn server-wide settings in force: %s", describe());
        }
    }

    private static final AtomicBoolean logged = new AtomicBoolean();

    /** Restores the compiled-in defaults. For tests; a running server never needs it. */
    public static synchronized void reset() {
        fromScopes.clear();
        logged.set(false);
        allowedInternalHosts = null;
        httpTimeoutMillis = DEFAULT_HTTP_TIMEOUT_MILLIS;
        maxResponseBytes = DEFAULT_MAX_RESPONSE_BYTES;
        httpDeadlineMillis = DEFAULT_HTTP_DEADLINE_MILLIS;
        httpMaxConcurrentPerCaller = DEFAULT_HTTP_MAX_CONCURRENT_PER_CALLER;
        clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS;
        maxCredentialLifetimeSeconds = DEFAULT_MAX_CREDENTIAL_LIFETIME_SECONDS;
        httpCacheSeconds = DEFAULT_HTTP_CACHE_SECONDS;
        httpMode = DEFAULT_HTTP_MODE;
    }

    private static Set<String> parseHosts(String value) {
        if (value == null || value.isBlank()) {
            return Collections.emptySet();
        }
        Set<String> hosts = new LinkedHashSet<>();
        for (String h : value.split(",")) {
            String t = SsrfGuard.normalizeHost(h);
            if (!t.isEmpty()) {
                hosts.add(t);
            }
        }
        return Collections.unmodifiableSet(hosts);
    }
}
