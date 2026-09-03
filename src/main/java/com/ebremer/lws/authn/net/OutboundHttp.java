/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Outbound HTTP policy for verifier fetches driven by attacker-influenced URLs (the OpenID and
 * self-signed CID verifiers dereference the credential's `sub`/`iss` and fetch OIDC discovery / JWKS).
 * Every such fetch is bounded in time and in the number of bytes consumed, resolves through
 * {@link GuardedDnsResolver} so it can only reach vetted addresses, and never follows a redirect.
 */
package com.ebremer.lws.authn.net;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.CloseableHttpClient;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.truststore.TruststoreProvider;

/**
 * Builds {@link SimpleHttp} GETs pre-configured with bounded timeouts, a response-size cap, redirect
 * following disabled, and SSRF-vetted name resolution.
 *
 * <p><strong>Why not the session's client.</strong> {@code SimpleHttp.doGet(url, session)} uses
 * Keycloak's server-wide HTTP client. That client resolves the target host itself, after
 * {@link SsrfGuard} has already resolved it — a rebinding window — and whether it follows redirects is
 * a deployment setting ({@code spi-connections-http-client-default-allow-redirects}, off by default,
 * but one flag away from letting a 302 walk past the guard). Neither is controllable per request.
 * This class therefore builds its own client with {@code disableRedirectHandling()} and
 * {@link GuardedDnsResolver}, while reusing Keycloak's configured truststore and hostname-verification
 * policy so private-CA deployments keep working.</p>
 *
 * <p>Set {@code lws.authn.http.mode=session} (or {@code LWS_AUTHN_HTTP_MODE=session}) to fall back to
 * the server-wide client — for a deployment that needs Keycloak's proxy mappings, which this client
 * does not replicate. That fallback is neither redirect-safe nor rebinding-safe.</p>
 *
 * @author Erich Bremer
 */
public final class OutboundHttp {

    private static final Logger log = Logger.getLogger(OutboundHttp.class);

    private OutboundHttp() {
    }

    /** Connect / read / connection-request timeout applied to each outbound fetch (milliseconds). */
    public static final int TIMEOUT_MS = 5_000;

    /**
     * Maximum response body the verifiers will consume. Controlled identifier documents, OIDC
     * discovery documents and JWK sets are all small (a few KB); 256&nbsp;KiB is a generous ceiling
     * that still rejects a hostile target streaming an unbounded body.
     */
    public static final long MAX_RESPONSE_BYTES = 256L * 1024L;

    private static final int POOL_SIZE = 16;
    private static final int MAX_PER_ROUTE = 4;

    /** Consecutive failures against one host that trip its breaker. */
    private static final int FAILURE_THRESHOLD = 5;
    /** How long failures accumulate, and how long the breaker then stays open (milliseconds). */
    private static final long FAILURE_WINDOW_MS = 10_000L;
    /** Upper bound on the number of hosts tracked by the breaker. */
    private static final int MAX_TRACKED_HOSTS = 1024;

    /** Thrown when a host is refused without a fetch because its breaker is open. */
    public static final class HostUnavailableException extends RuntimeException {
        public HostUnavailableException(String message) {
            super(message);
        }
    }

    private static volatile CloseableHttpClient guardedClient;

    /**
     * A {@link SimpleHttp} GET with the bounded timeouts and response-size cap already applied, whose
     * URL has passed {@link SsrfGuard} and whose host is not currently short-circuited.
     *
     * @throws SsrfGuard.BlockedException if the URL must not be fetched
     * @throws HostUnavailableException if the host has failed repeatedly in the last few seconds
     */
    public static SimpleHttp get(String url, KeycloakSession session) {
        // The breaker comes first: its whole purpose is to stop paying for a host that keeps failing,
        // and resolving the name before consulting it would pay part of that cost anyway.
        requireClosedCircuit(hostOf(url));
        SsrfGuard.verify(url);
        HttpClient client = usingSessionClient() ? null : guardedClient(session);
        SimpleHttp request = client == null
                ? SimpleHttp.doGet(url, session).setMaxConsumedResponseSize(MAX_RESPONSE_BYTES)
                : LwsSimpleHttp.get(url, client, MAX_RESPONSE_BYTES);
        return request
                .connectTimeoutMillis(TIMEOUT_MS)
                .connectionRequestTimeoutMillis(TIMEOUT_MS)
                .socketTimeOutMillis(TIMEOUT_MS);
    }

    // ------------------------------------------------------------------ the shared, guarded client

    private static CloseableHttpClient guardedClient(KeycloakSession session) {
        CloseableHttpClient existing = guardedClient;
        if (existing != null) {
            return existing;
        }
        synchronized (OutboundHttp.class) {
            if (guardedClient == null) {
                guardedClient = build(session);
            }
            return guardedClient;
        }
    }

    /**
     * Builds the client once, for the lifetime of the provider. The truststore is server-wide rather
     * than per-realm, so taking it from whichever session builds the client first is safe; a truststore
     * change still needs a Keycloak restart, exactly as it does for Keycloak's own client.
     */
    private static CloseableHttpClient build(KeycloakSession session) {
        GuardedClientBuilder builder = new GuardedClientBuilder();
        builder.disableRedirectHandling()
                .disableCookies(true)
                .socketTimeout(TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .establishConnectionTimeout(TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .connectionRequestTimeout(TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .connectionPoolSize(POOL_SIZE)
                .maxPooledPerRoute(MAX_PER_ROUTE)
                .connectionTTL(5, TimeUnit.MINUTES)
                .maxConnectionIdleTime(1, TimeUnit.MINUTES);

        TruststoreProvider truststore = session == null ? null : session.getProvider(TruststoreProvider.class);
        if (truststore != null && truststore.getTruststore() != null) {
            builder.hostnameVerification(truststore.getPolicy()).trustStore(truststore.getTruststore());
        } else {
            log.debug("No Keycloak TruststoreProvider configured; LWS outbound fetches use the JVM default trust store");
        }
        return builder.build();
    }

    /**
     * Keycloak's HTTP client builder, with our DNS resolver installed on the Apache builder underneath.
     * Keycloak's {@code build()} never calls {@code setConnectionManager}, so Apache creates the pooling
     * manager itself and honours the resolver set here.
     */
    private static final class GuardedClientBuilder extends org.keycloak.connections.httpclient.HttpClientBuilder {
        private GuardedClientBuilder() {
            getApacheHttpClientBuilder().setDnsResolver(new GuardedDnsResolver());
        }
    }

    private static boolean usingSessionClient() {
        String mode = System.getProperty("lws.authn.http.mode");
        if (mode == null || mode.isBlank()) {
            mode = System.getenv("LWS_AUTHN_HTTP_MODE");
        }
        return mode != null && "session".equalsIgnoreCase(mode.trim());
    }

    // -------------------------------------------------------------------------- per-host breaker

    private static final Map<String, Circuit> CIRCUITS = new LinkedHashMap<>(64, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Circuit> eldest) {
            return size() > MAX_TRACKED_HOSTS;
        }
    };

    private static final class Circuit {
        private int failures;
        private long windowEndsAt;
    }

    /**
     * Records that a fetch of {@code url} failed. Enough failures in a short window trip the host's
     * breaker, so an unauthenticated caller cannot use a dead or hostile target to make this server
     * spend five seconds per request on its behalf.
     */
    public static void recordFailure(String url) {
        String host = hostOf(url);
        if (host == null) {
            return;
        }
        long now = System.currentTimeMillis();
        synchronized (CIRCUITS) {
            Circuit circuit = CIRCUITS.computeIfAbsent(host, h -> new Circuit());
            if (now > circuit.windowEndsAt) {
                circuit.failures = 0;
            }
            circuit.failures++;
            circuit.windowEndsAt = now + FAILURE_WINDOW_MS;
        }
    }

    /** Clears any recorded failures for the host of {@code url}, after a fetch succeeds. */
    public static void recordSuccess(String url) {
        String host = hostOf(url);
        if (host == null) {
            return;
        }
        synchronized (CIRCUITS) {
            CIRCUITS.remove(host);
        }
    }

    private static void requireClosedCircuit(String host) {
        if (host == null) {
            return;
        }
        long now = System.currentTimeMillis();
        synchronized (CIRCUITS) {
            Circuit circuit = CIRCUITS.get(host);
            if (circuit == null) {
                return;
            }
            if (now > circuit.windowEndsAt) {
                CIRCUITS.remove(host);
                return;
            }
            if (circuit.failures >= FAILURE_THRESHOLD) {
                throw new HostUnavailableException("host '" + host + "' recently failed repeatedly; not retrying yet");
            }
        }
    }

    /** Test seam: forget every recorded failure. */
    public static void resetCircuits() {
        synchronized (CIRCUITS) {
            CIRCUITS.clear();
        }
    }

    private static String hostOf(String url) {
        try {
            String host = URI.create(url).getHost();
            return host == null ? null : host.toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return null;
        }
    }
}
