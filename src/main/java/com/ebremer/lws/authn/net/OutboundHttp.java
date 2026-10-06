/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Outbound HTTP policy for verifier fetches driven by attacker-influenced URLs (the OpenID and
 * self-signed CID verifiers dereference the credential's `sub`/`iss` and fetch OIDC discovery / JWKS).
 * Every such fetch is bounded in time and in the number of bytes consumed, resolves through
 * {@link GuardedDnsResolver} so it can only reach vetted addresses, and follows a redirect only when
 * dereferencing a subject, re-vetting each hop.
 */
package com.ebremer.lws.authn.net;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

import javax.net.ssl.SSLHandshakeException;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.conn.ConnectionPoolTimeoutException;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.truststore.TruststoreProvider;

import com.ebremer.lws.authn.config.ServerSettings;
import com.ebremer.lws.authn.verify.VerifyAccess;

/**
 * Fetches a document for a verifier: SSRF-vetted name resolution, redirects only where a subject is
 * dereferenced and then re-vetted per hop, bounded timeouts, a hard deadline on the whole exchange, a
 * response-size cap, and a bound on how many fetches one caller may have in flight.
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
 * <p>Set {@code http-mode=session} (or {@code lws.authn.http.mode}, {@code LWS_AUTHN_HTTP_MODE}) to fetch
 * through the server-wide client instead — for a deployment that needs Keycloak's proxy mappings, which this
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

    /** Failures against one origin, none further apart than {@link #FAILURE_WINDOW_MS}, that trip its breaker. */
    private static final int FAILURE_THRESHOLD = 5;
    /** How long failures accumulate, and how long the breaker then stays open (milliseconds). */
    private static final long FAILURE_WINDOW_MS = 10_000L;
    /** Upper bound on the number of origins tracked by the breaker. */
    private static final int MAX_TRACKED_HOSTS = 1024;

    /** Thrown when an origin is refused without a fetch because its breaker is open. */
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
     * @param cached      whether this came from the cache rather than the network just now
     */
    public record Fetched(int status, String contentType, String body, boolean cached) {

        /** A response from the network. */
        public Fetched(int status, String contentType, String body) {
            this(status, contentType, body, false);
        }
    }

    /** Documents fetched recently, for as long as their servers and {@code http-cache-seconds} allow (R-26). */
    private static final DocumentCache CACHE = new DocumentCache();

    /**
     * How soon a document may be fetched again past its cached copy — when a JWT names a key the cached
     * JWK set does not have, say, because the issuer has just rotated. Without a floor, a caller sending
     * tokens with made-up {@code kid}s could make every one of them cost a fetch.
     */
    static final long REFETCH_INTERVAL_MS = 30_000L;

    /** Upper bound on the number of URLs whose last refetch is remembered. */
    private static final int MAX_TRACKED_REFETCHES = 1024;

    private static final Map<String, Long> REFETCHED = new LinkedHashMap<>(64, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
            return size() > MAX_TRACKED_REFETCHES;
        }
    };

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
     * The most redirects {@link #dereference} follows. Three is enough for an http→https upgrade, a
     * trailing-slash fix and a {@code 303 See Other} from a WebID to its document, and no more.
     */
    public static final int MAX_REDIRECTS = 3;

    /**
     * GETs {@code url} for a verifier, following no redirect: a {@code 3xx} is returned as it is. For
     * the documents whose URL is itself the trust anchor — OpenID discovery and its {@code jwks_uri}, a
     * {@code did:web} document — and that are not identifiers people put in a browser.
     *
     * @param accept  the {@code Accept} header to send, or {@code null}
     * @param session the request's session: whose caller the fetch counts against, and — in
     *                {@code session} mode — whose HTTP client fetches. May be {@code null} (tests).
     * @throws SsrfGuard.BlockedException  if the URL must not be fetched
     * @throws HostUnavailableException    if the origin could not be reached repeatedly in the last few seconds
     * @throws CallerBusyException         if the caller already has its share of fetches in flight
     * @throws ResponseTooLargeException   if the body is over the size cap
     * @throws IOException                 if the fetch fails or overruns its deadline
     */
    public static Fetched fetch(String url, String accept, KeycloakSession session) throws IOException {
        return get(url, accept, session, 0, true);
    }

    /**
     * GETs a subject's document, following up to {@link #MAX_REDIRECTS} redirects (R-29).
     *
     * <p>A WebID that answers {@code 303 See Other} — the httpRange-14 pattern, an identifier for a person
     * redirecting to the document about them — or redirects http to https used to fail as "did not return
     * a controlled identifier document". Following is safe because nothing about the target is taken on
     * trust: each hop is checked by {@link SsrfGuard} and its origin's breaker before it is requested,
     * {@link GuardedDnsResolver} vets the address actually connected to, a downgrade to plain http is
     * refused as any http URL is, and the whole chain shares one deadline. The document that comes back
     * must still have the <em>original</em> subject as its {@code id}; where it was found changes
     * nothing about whom it must describe.</p>
     *
     * @throws SsrfGuard.BlockedException if any hop must not be fetched
     * @see #fetch for the other exceptions
     */
    public static Fetched dereference(String url, String accept, KeycloakSession session) throws IOException {
        return get(url, accept, session, MAX_REDIRECTS, true);
    }

    /**
     * Fetches {@code url} as {@link #fetch} does but past the cache, and caches what comes back — unless
     * it was fetched in the last {@link #REFETCH_INTERVAL_MS}, from the cache's copy or by an earlier
     * refetch, in which case nothing is fetched and {@code null} is returned.
     */
    public static Fetched refetch(String url, String accept, KeycloakSession session) throws IOException {
        long now = clock.getAsLong();
        long fetchedAt = CACHE.fetchedAt(cacheKey(url, accept, 0));
        synchronized (REFETCHED) {
            Long last = REFETCHED.get(url);
            if ((last != null && now - last < REFETCH_INTERVAL_MS)
                    || (fetchedAt >= 0 && now - fetchedAt < REFETCH_INTERVAL_MS)) {
                return null;
            }
            REFETCHED.put(url, now);
        }
        return get(url, accept, session, 0, false);
    }

    /** Test seam: forget every cached document and refetch. */
    public static void clearCache() {
        CACHE.clear();
        synchronized (REFETCHED) {
            REFETCHED.clear();
        }
    }

    /** Test seam: how many documents are cached. */
    static int cachedDocuments() {
        return CACHE.size();
    }

    private static String cacheKey(String url, String accept, int maxRedirects) {
        // Following redirects or not can give different answers for one URL, and so can the Accept.
        return (maxRedirects > 0 ? "follow " : "exact ") + url + " " + accept;
    }

    /** One response, with where it redirects to if it does, and how long it may be cached. */
    private record Hop(Fetched fetched, String location, String cacheControl) {
    }

    private static Fetched get(String url, String accept, KeycloakSession session, int maxRedirects,
                               boolean fromCache) throws IOException {
        // A fresh copy is used without asking the network anything — not even DNS, which would tell the
        // subject's name server what the cache exists to keep quiet. It was vetted when it was fetched.
        long cacheSeconds = ServerSettings.httpCacheSeconds();
        String key = cacheKey(url, accept, maxRedirects);
        if (fromCache && cacheSeconds > 0) {
            Fetched cached = CACHE.get(key, clock.getAsLong());
            if (cached != null) {
                return cached;
            }
        }
        // The breaker comes first: its whole purpose is to stop paying for an origin that cannot be
        // reached, and resolving the name before consulting it would pay part of that cost anyway.
        String origin = originOf(url);
        requireClosedCircuit(origin);
        SsrfGuard.verify(url);
        String caller = VerifyAccess.callerKey(session);
        acquire(caller);
        try {
            long deadlineAt = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(deadlineMillis());
            String current = url;
            for (int hop = 0; ; hop++) {
                if (hop > 0) {
                    origin = originOf(current);
                    requireClosedCircuit(origin);
                    SsrfGuard.verify(current);
                }
                Hop answer;
                try {
                    answer = execute(current, accept, client(session), deadlineAt);
                    markSuccess(origin); // it answered; whatever the answer, the origin is reachable
                } catch (IOException e) {
                    if (isOriginFailure(e)) {
                        markFailure(origin);
                    }
                    throw e;
                }
                if (hop >= maxRedirects || answer.location() == null) {
                    Fetched fetched = answer.fetched();
                    if (fetched.status() == 200 && cacheSeconds > 0) {
                        long seconds = DocumentCache.freshnessSeconds(answer.cacheControl(), cacheSeconds);
                        CACHE.put(key, new Fetched(200, fetched.contentType(), fetched.body(), true),
                                clock.getAsLong(), TimeUnit.SECONDS.toMillis(seconds));
                    }
                    return fetched;
                }
                current = resolve(current, answer.location());
            }
        } finally {
            release(caller);
        }
    }

    /** A redirect's {@code Location}, resolved against the URL that sent it, without any fragment. */
    private static String resolve(String base, String location) throws IOException {
        try {
            String target = URI.create(base).resolve(location.trim()).toString();
            int fragment = target.indexOf('#');
            return fragment < 0 ? target : target.substring(0, fragment);
        } catch (IllegalArgumentException malformed) {
            throw new IOException("redirect to a malformed Location", malformed);
        }
    }

    /**
     * Whether a failed fetch says the <em>origin</em> cannot be reached, as opposed to something about
     * the one URL that was asked for (R-02).
     *
     * <p>Only the first kind may count towards the breaker, because the URL is the caller's choice. A
     * breaker that counted 404s, slow or oversized bodies, or a document that would not parse let any
     * caller trip it against any origin — five credentials whose {@code sub} named a missing path on
     * this server's own host stopped every hosted-WebID verification — and then kept it tripped. What
     * remains is what no path can produce: the name does not resolve (to an address this deployment may
     * reach), the connection is refused or never completes, or the TLS handshake fails. A slow or hostile
     * server is not the breaker's to handle; the deadline, the size cap and the per-caller bound already
     * bound what it can cost (R-01).</p>
     *
     * <p>Not counted although they look like connection failures: waiting too long for a connection
     * from the pool ({@link ConnectionPoolTimeoutException}, a subclass of the connect timeout), which
     * is about this server's load, not the origin; and an abort at the deadline.</p>
     */
    static boolean isOriginFailure(IOException e) {
        if (e instanceof ConnectionPoolTimeoutException) {
            return false;
        }
        return e instanceof ConnectTimeoutException
                || e instanceof ConnectException
                || e instanceof UnknownHostException
                || e instanceof SSLHandshakeException;
    }

    /** The statuses that send a GET elsewhere with a {@code Location}: 301, 302, 303, 307 and 308. */
    private static boolean isRedirect(int status) {
        return status == 301 || status == 302 || status == 303 || status == 307 || status == 308;
    }

    private static Hop execute(String url, String accept, CloseableHttpClient client, long deadlineAt)
            throws IOException {
        long remaining = TimeUnit.NANOSECONDS.toMillis(deadlineAt - System.nanoTime());
        if (remaining <= 0) {
            throw new IOException("the fetch ran out of time following redirects");
        }
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
        ScheduledFuture<?> deadline = DEADLINES.schedule(request::abort, remaining, TimeUnit.MILLISECONDS);
        try (CloseableHttpResponse response = client.execute(request)) {
            int status = response.getStatusLine().getStatusCode();
            Header type = response.getFirstHeader("Content-Type");
            String contentType = type == null ? null : type.getValue();
            if (status != 200) {
                // No verifier reads anything but a 200, so an error body is never worth reading — and
                // closing it normally would read it anyway, to keep the connection.
                request.abort();
                Header location = isRedirect(status) ? response.getFirstHeader("Location") : null;
                return new Hop(new Fetched(status, contentType, null),
                        location == null || location.getValue().isBlank() ? null : location.getValue(), null);
            }
            // Several Cache-Control fields are one list (RFC 9110 §5.3).
            StringBuilder cacheControl = new StringBuilder();
            for (Header field : response.getHeaders("Cache-Control")) {
                cacheControl.append(cacheControl.length() == 0 ? "" : ",").append(field.getValue());
            }
            return new Hop(new Fetched(status, contentType, readBody(response.getEntity(), request)), null,
                    cacheControl.length() == 0 ? null : cacheControl.toString());
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

    /** {@code http-mode=session}: see {@link ServerSettings#httpMode()}. */
    private static boolean usingSessionClient() {
        return "session".equals(ServerSettings.httpMode());
    }

    // ------------------------------------------------------------------------ per-origin breaker

    private static final Map<String, Circuit> CIRCUITS = new LinkedHashMap<>(64, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Circuit> eldest) {
            return size() > MAX_TRACKED_HOSTS;
        }
    };

    /**
     * The breaker's and the cache's clock, in milliseconds: monotonic, since neither means a time of day
     * and a wall-clock step backwards would hold a circuit open, or a document fresh, for that much
     * longer (R-36). A test seam.
     */
    private static final LongSupplier MONOTONIC = () -> System.nanoTime() / 1_000_000L;

    private static volatile LongSupplier clock = MONOTONIC;

    private static final class Circuit {
        private int failures;
        /** Closed: when the failures so far are forgotten. Open: when it closes again. */
        private long windowEndsAt;
        private boolean open;
    }

    /**
     * Records that {@code url}'s origin could not be reached. Enough of these close together open its
     * breaker for {@link #FAILURE_WINDOW_MS}, so a dead origin does not cost every caller a connect
     * timeout. Once open, the window is fixed: a failure reported by a fetch that was already in flight
     * does not extend it, and nothing else can, since a refused fetch is never attempted.
     */
    static void recordFailure(String url) {
        markFailure(originOf(url));
    }

    /** Forgets any recorded failures for {@code url}'s origin, as an answer from it does. */
    static void recordSuccess(String url) {
        markSuccess(originOf(url));
    }

    private static void markFailure(String origin) {
        if (origin == null) {
            return;
        }
        long now = clock.getAsLong();
        synchronized (CIRCUITS) {
            Circuit circuit = CIRCUITS.computeIfAbsent(origin, o -> new Circuit());
            if (circuit.open) {
                if (now <= circuit.windowEndsAt) {
                    return;
                }
                circuit.open = false;
                circuit.failures = 0;
            } else if (now > circuit.windowEndsAt) {
                circuit.failures = 0;
            }
            circuit.failures++;
            circuit.windowEndsAt = now + FAILURE_WINDOW_MS;
            circuit.open = circuit.failures >= FAILURE_THRESHOLD;
        }
    }

    private static void markSuccess(String origin) {
        if (origin == null) {
            return;
        }
        synchronized (CIRCUITS) {
            CIRCUITS.remove(origin);
        }
    }

    private static void requireClosedCircuit(String origin) {
        if (origin == null) {
            return;
        }
        long now = clock.getAsLong();
        synchronized (CIRCUITS) {
            Circuit circuit = CIRCUITS.get(origin);
            if (circuit == null) {
                return;
            }
            if (now > circuit.windowEndsAt) {
                CIRCUITS.remove(origin);
                return;
            }
            if (circuit.open) {
                throw new HostUnavailableException("'" + origin + "' could not be reached repeatedly; not retrying yet");
            }
        }
    }

    /** Test seam: forget every recorded failure, and go back to the real clock. */
    public static void resetCircuits() {
        synchronized (CIRCUITS) {
            CIRCUITS.clear();
        }
        clock = MONOTONIC;
    }

    /** Test seam: run the breaker and the cache on {@code millis} instead of the monotonic clock. */
    static void useClock(LongSupplier millis) {
        clock = millis;
    }

    /**
     * The breaker's key: scheme, host and port, with the default port made explicit. Keyed on the host
     * alone, an unreachable {@code http://host:8080} would also have refused {@code https://host}.
     */
    static String originOf(String url) {
        if (url == null) {
            return null;
        }
        try {
            URI uri = URI.create(url);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null) {
                return null;
            }
            scheme = scheme.toLowerCase(Locale.ROOT);
            int port = uri.getPort() >= 0 ? uri.getPort() : "https".equals(scheme) ? 443 : "http".equals(scheme) ? 80 : -1;
            return scheme + "://" + host.toLowerCase(Locale.ROOT) + ":" + port;
        } catch (Exception e) {
            return null;
        }
    }
}
