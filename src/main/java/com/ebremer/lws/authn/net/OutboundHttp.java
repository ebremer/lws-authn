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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.truststore.TruststoreProvider;

import com.ebremer.lws.authn.config.ServerSettings;
import com.ebremer.lws.authn.verify.VerifyAccess;

/**
 * Fetches a document for a verifier: SSRF-vetted name resolution, no redirects, bounded timeouts, a
 * hard deadline on the whole exchange, a response-size cap, and a bound on how many fetches one caller
 * may have in flight.
 *
 * <p><strong>Why not the session's client.</strong> Keycloak's server-wide HTTP client resolves the
 * target host itself, after {@link SsrfGuard} has already resolved it — a rebinding window — and
 * whether it follows redirects is a deployment setting
 * ({@code spi-connections-http-client-default-allow-redirects}, off by default, but one flag away from
 * letting a 302 walk past the guard). This class therefore builds its own client with
 * {@code disableRedirectHandling()} and {@link GuardedDnsResolver}, while reusing Keycloak's configured
 * truststore and hostname-verification policy so private-CA deployments keep working.</p>
 *
 * <p><strong>Why not Keycloak's {@code SimpleHttp}.</strong> It bounds each read but not the exchange,
 * and when its size cap trips it closes the stream, which makes Apache HttpClient read and discard the
 * rest of the body to keep the connection reusable. A server trickling one byte just inside the read
 * timeout, or streaming without end, therefore held a pooled connection and a worker thread for as long
 * as it liked; sixteen such fetches exhausted the pool and stopped every verification on the server
 * (R-01). {@link #fetch} instead aborts the request — which shuts the socket rather than draining it —
 * at a deadline, on a declared length over the cap, and as soon as the body passes it.</p>
 *
 * <p>Set {@code lws.authn.http.mode=session} (or {@code LWS_AUTHN_HTTP_MODE=session}) to fetch through
 * the server-wide client instead — for a deployment that needs Keycloak's proxy mappings, which this
 * client does not replicate. Redirects stay off per request and the deadline, cap and caller bound
 * still apply, but name resolution is then Keycloak's: that fallback is not rebinding-safe.</p>
 *
 * @author Erich Bremer
 */
public final class OutboundHttp {

    private static final Logger log = Logger.getLogger(OutboundHttp.class);

    private OutboundHttp() {
    }

    /**
     * Connect / read / connection-request timeout applied to each outbound fetch (milliseconds).
     * Configurable as {@code http-timeout-millis}; see {@link ServerSettings}.
     */
    public static int timeoutMillis() {
        return ServerSettings.httpTimeoutMillis();
    }

    /**
     * Maximum response body the verifiers will consume. Controlled identifier documents, OIDC
     * discovery documents and JWK sets are all small (a few KB); the 256&nbsp;KiB default is a generous
     * ceiling that still rejects a hostile target streaming an unbounded body. Configurable as
     * {@code http-max-response-bytes}.
     */
    public static long maxResponseBytes() {
        return ServerSettings.maxResponseBytes();
    }

    /**
     * The total time one fetch may take, connection and body included, before it is aborted
     * (milliseconds). Configurable as {@code http-deadline-millis}.
     */
    public static int deadlineMillis() {
        return ServerSettings.httpDeadlineMillis();
    }

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

    /** Thrown when the caller already has as many fetches in flight as it may. */
    public static final class CallerBusyException extends RuntimeException {
        public CallerBusyException(String message) {
            super(message);
        }
    }

    /** Thrown when a response body is, or declares itself, larger than {@link #maxResponseBytes()}. */
    public static final class ResponseTooLargeException extends IOException {
        public ResponseTooLargeException(String message) {
            super(message);
        }
    }

    /**
     * A completed fetch.
     *
     * @param status      the HTTP status
     * @param contentType the {@code Content-Type} the server declared, or {@code null}
     * @param body        the decoded body for a {@code 200}; {@code null} for any other status, whose
     *                    body is not read at all
     */
    public record Fetched(int status, String contentType, String body) {
    }

    private static volatile CloseableHttpClient guardedClient;

    /**
     * Aborts fetches that overrun their deadline. One daemon thread: an abort only shuts a socket, and
     * a cancelled task is removed at once, so the queue holds no more than the fetches in flight.
     */
    private static final ScheduledThreadPoolExecutor DEADLINES = deadlineTimer();

    private static ScheduledThreadPoolExecutor deadlineTimer() {
        ScheduledThreadPoolExecutor timer = new ScheduledThreadPoolExecutor(1, task -> {
            Thread thread = new Thread(task, "lws-authn-fetch-deadline");
            thread.setDaemon(true);
            return thread;
        });
        timer.setRemoveOnCancelPolicy(true);
        return timer;
    }

    /** Fetches each caller has in flight, keyed by {@link VerifyAccess#callerKey}. Entries at zero are removed. */
    private static final ConcurrentHashMap<String, Integer> IN_FLIGHT = new ConcurrentHashMap<>();

    /**
     * GETs {@code url} for a verifier.
     *
     * @param accept  the {@code Accept} header to send, or {@code null}
     * @param session the request's session: whose caller the fetch counts against, and — in
     *                {@code session} mode — whose HTTP client fetches. May be {@code null} (tests).
     * @throws SsrfGuard.BlockedException  if the URL must not be fetched
     * @throws HostUnavailableException    if the host has failed repeatedly in the last few seconds
     * @throws CallerBusyException         if the caller already has its share of fetches in flight
     * @throws ResponseTooLargeException   if the body is over the size cap
     * @throws IOException                 if the fetch fails or overruns its deadline
     */
    public static Fetched fetch(String url, String accept, KeycloakSession session) throws IOException {
        // The breaker comes first: its whole purpose is to stop paying for a host that keeps failing,
        // and resolving the name before consulting it would pay part of that cost anyway.
        requireClosedCircuit(hostOf(url));
        SsrfGuard.verify(url);
        String caller = VerifyAccess.callerKey(session);
        acquire(caller);
        try {
            return execute(url, accept, client(session));
        } finally {
            release(caller);
        }
    }

    private static Fetched execute(String url, String accept, CloseableHttpClient client) throws IOException {
        int timeout = timeoutMillis();
        HttpGet request = new HttpGet(url);
        request.setConfig(RequestConfig.custom()
                .setConnectTimeout(timeout)
                .setSocketTimeout(timeout)
                .setConnectionRequestTimeout(timeout)
                // Already off on the guarded client; set per request too so session mode cannot follow one.
                .setRedirectsEnabled(false)
                .build());
        if (accept != null) {
            request.setHeader("Accept", accept);
        }
        // abort() shuts the connection whatever the request is doing — waiting for a pooled connection,
        // connecting, or blocked in a read of the body — which is what makes the deadline a deadline.
        ScheduledFuture<?> deadline = DEADLINES.schedule(request::abort, deadlineMillis(), TimeUnit.MILLISECONDS);
        try (CloseableHttpResponse response = client.execute(request)) {
            int status = response.getStatusLine().getStatusCode();
            Header type = response.getFirstHeader("Content-Type");
            String contentType = type == null ? null : type.getValue();
            if (status != 200) {
                // No verifier reads anything but a 200, so an error body is never worth reading — and
                // closing it normally would read it anyway, to keep the connection.
                request.abort();
                return new Fetched(status, contentType, null);
            }
            return new Fetched(status, contentType, readBody(response.getEntity(), request));
        } finally {
            deadline.cancel(false);
        }
    }

    /**
     * Reads at most {@link #maxResponseBytes()} of {@code entity}. Over the cap — declared or actual —
     * the request is aborted before the stream is closed, so the rest of the body is never read.
     */
    private static String readBody(HttpEntity entity, HttpGet request) throws IOException {
        if (entity == null) {
            return "";
        }
        long max = maxResponseBytes();
        long declared = entity.getContentLength();
        if (declared > max) {
            request.abort();
            throw new ResponseTooLargeException("response declares " + declared + " bytes; the limit is " + max);
        }
        ByteArrayOutputStream body = new ByteArrayOutputStream(declared > 0 ? (int) declared : 8192);
        try (InputStream in = entity.getContent()) {
            byte[] chunk = new byte[8192];
            long total = 0;
            int n;
            while ((n = in.read(chunk)) != -1) {
                total += n;
                if (total > max) {
                    request.abort();
                    throw new ResponseTooLargeException("response exceeds the limit of " + max + " bytes");
                }
                body.write(chunk, 0, n);
            }
        }
        return body.toString(charsetOf(entity));
    }

    private static Charset charsetOf(HttpEntity entity) {
        try {
            ContentType type = ContentType.get(entity);
            Charset charset = type == null ? null : type.getCharset();
            return charset == null ? StandardCharsets.UTF_8 : charset;
        } catch (RuntimeException unreadable) {
            return StandardCharsets.UTF_8;
        }
    }

    // ------------------------------------------------------------------ per-caller concurrency

    private static void acquire(String caller) {
        int limit = ServerSettings.httpMaxConcurrentPerCaller();
        IN_FLIGHT.compute(caller, (key, inFlight) -> {
            int current = inFlight == null ? 0 : inFlight;
            if (current >= limit) {
                throw new CallerBusyException("caller already has " + current + " outbound fetches in flight");
            }
            return current + 1;
        });
    }

    private static void release(String caller) {
        IN_FLIGHT.computeIfPresent(caller, (key, inFlight) -> inFlight <= 1 ? null : inFlight - 1);
    }

    // ------------------------------------------------------------------ the HTTP client

    private static CloseableHttpClient client(KeycloakSession session) {
        if (usingSessionClient() && session != null) {
            return session.getProvider(HttpClientProvider.class).getHttpClient();
        }
        return guardedClient(session);
    }

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
                .socketTimeout(timeoutMillis(), TimeUnit.MILLISECONDS)
                .establishConnectionTimeout(timeoutMillis(), TimeUnit.MILLISECONDS)
                .connectionRequestTimeout(timeoutMillis(), TimeUnit.MILLISECONDS)
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
