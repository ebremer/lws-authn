/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.http.conn.ConnectionPoolTimeoutException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.keycloak.common.ClientConnection;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;

import com.ebremer.lws.authn.config.ServerSettings;

/**
 * The verifiers' outbound fetch, exercised against a real HTTP server rather than only reasoned about.
 *
 * <p>P0-5 and P0-6: the client is built with redirect following disabled and {@link GuardedDnsResolver}
 * installed, which is only worth anything if it actually builds and behaves that way — the resolver is
 * set on the Apache builder underneath Keycloak's wrapper, and Apache honours it only because Keycloak
 * never installs its own connection manager.</p>
 *
 * <p>R-01: a hostile server must not be able to hold a fetch open. A per-read timeout bounds each read
 * but not their sum, and closing an over-long body normally makes Apache read the rest of it, so each
 * of the servers below used to keep a pooled connection and a worker thread busy for as long as it
 * liked. The deadline here is shortened to keep the tests quick; the production default is ten
 * seconds.</p>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OutboundHttpClientTest {

    private static final String ALLOWLIST_PROPERTY = "lws.authn.allowedInternalHosts";
    private static final String DEADLINE_PROPERTY = "lws.authn.http.deadlineMillis";
    private static final String PER_CALLER_PROPERTY = "lws.authn.http.maxConcurrentPerCaller";
    private static final String TIMEOUT_PROPERTY = "lws.authn.http.timeoutMillis";
    private static final long DEADLINE_MILLIS = 1_500;

    private HttpServer server;
    private ExecutorService handlers;
    private int port;
    private String previousAllowlist;
    private final AtomicLong endlessBytesSent = new AtomicLong();
    private final java.util.concurrent.atomic.AtomicInteger dripsStarted = new java.util.concurrent.atomic.AtomicInteger();
    private volatile boolean dripsReleased;
    /** Requests each counted path has had. */
    private final java.util.Map<String, java.util.concurrent.atomic.AtomicInteger> hits =
            new java.util.concurrent.ConcurrentHashMap<>();

    @BeforeAll
    void startServer() throws Exception {
        // The test targets are on loopback, so loopback has to be an intended target here — the same
        // opt-in a single-box Keycloak needs to dereference its own controlled identifier documents.
        previousAllowlist = System.getProperty(ALLOWLIST_PROPERTY);
        System.setProperty(ALLOWLIST_PROPERTY, "localhost");
        System.setProperty(DEADLINE_PROPERTY, String.valueOf(DEADLINE_MILLIS));
        System.setProperty(PER_CALLER_PROPERTY, "2");
        ServerSettings.contribute("test", null);

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        port = server.getAddress().getPort();
        server.createContext("/cid", exchange -> respond(exchange, 200, "the controlled identifier document"));
        server.createContext("/elsewhere", exchange -> respond(exchange, 200, "the redirect target"));
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().add("Location", "http://localhost:" + port + "/elsewhere");
            respond(exchange, 302, "");
        });
        // Each answers 200 and counts its requests; the path says what Cache-Control it sends.
        for (String[] counted : new String[][]{{"/counted", null}, {"/no-store", "no-store"},
                {"/max-age-5", "public, max-age=5"}, {"/missing-counted", null}}) {
            server.createContext(counted[0], exchange -> {
                hits.computeIfAbsent(counted[0], p -> new java.util.concurrent.atomic.AtomicInteger()).incrementAndGet();
                if (counted[1] != null) {
                    exchange.getResponseHeaders().add("Cache-Control", counted[1]);
                }
                respond(exchange, counted[0].startsWith("/missing") ? 404 : 200, "document " + counted[0]);
            });
        }
        server.createContext("/see-other", exchange -> {
            exchange.getResponseHeaders().add("Location", "/cid#fragment-dropped");
            respond(exchange, 303, "");
        });
        server.createContext("/loop", exchange -> {
            exchange.getResponseHeaders().add("Location", "/loop");
            respond(exchange, 302, "");
        });
        server.createContext("/to-unlisted", exchange -> {
            // https, so it is the address 127.0.0.1 that is refused, not the scheme
            exchange.getResponseHeaders().add("Location", "https://127.0.0.1:" + port + "/cid");
            respond(exchange, 307, "");
        });
        // One byte every 200 ms, without end: every read returns well inside the read timeout.
        server.createContext("/trickle", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                for (int i = 0; i < 300; i++) {
                    out.write('x');
                    out.flush();
                    Thread.sleep(200);
                }
            } catch (IOException | InterruptedException clientGaveUp) {
                // expected: the fetch aborts
            }
        });
        // One byte every 50 ms for ten seconds, or until released: holds a pooled connection, every read
        // inside any timeout.
        server.createContext("/drip", exchange -> {
            dripsStarted.incrementAndGet();
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream out = exchange.getResponseBody()) {
                for (int i = 0; i < 200 && !dripsReleased; i++) {
                    out.write('x');
                    out.flush();
                    Thread.sleep(50);
                }
            } catch (IOException | InterruptedException clientGaveUp) {
                // expected: the fetch aborts
            }
        });
        // As fast as the socket will take it, without end.
        server.createContext("/endless", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            byte[] chunk = new byte[64 * 1024];
            try (OutputStream out = exchange.getResponseBody()) {
                while (!Thread.currentThread().isInterrupted()) {
                    out.write(chunk);
                    endlessBytesSent.addAndGet(chunk.length);
                }
            } catch (IOException clientGaveUp) {
                // expected: the fetch aborts
            }
        });
        // Declares a gigabyte, then stalls.
        server.createContext("/huge", exchange -> {
            exchange.sendResponseHeaders(200, 1_000_000_000L);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write("{".getBytes(StandardCharsets.UTF_8));
                out.flush();
                Thread.sleep(10_000);
            } catch (IOException | InterruptedException clientGaveUp) {
                // expected
            }
        });
        // Accepts the request and never answers.
        server.createContext("/silent", exchange -> {
            try {
                Thread.sleep(10_000);
                respond(exchange, 200, "too late");
            } catch (IOException | InterruptedException clientGaveUp) {
                // expected
            }
        });
        handlers = Executors.newCachedThreadPool();
        server.setExecutor(handlers);
        server.start();
    }

    @AfterAll
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
        if (handlers != null) {
            handlers.shutdownNow();
        }
        if (previousAllowlist == null) {
            System.clearProperty(ALLOWLIST_PROPERTY);
        } else {
            System.setProperty(ALLOWLIST_PROPERTY, previousAllowlist);
        }
        System.clearProperty(DEADLINE_PROPERTY);
        System.clearProperty(PER_CALLER_PROPERTY);
        ServerSettings.reset();
        OutboundHttp.resetCircuits();
    }

    /** These test the network path, which a cached document skips. */
    @BeforeEach
    void emptyTheCache() {
        OutboundHttp.clearCache();
        hits.clear();
    }

    @AfterEach
    void forgetFailures() {
        OutboundHttp.resetCircuits();
        OutboundHttp.clearCache();
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    /**
     * The whole custom-client path works end to end: Keycloak's Apache builder accepts the resolver,
     * and a fetch completes.
     */
    @Test
    void fetchesThroughTheGuardedClient() throws Exception {
        OutboundHttp.Fetched response = OutboundHttp.fetch(url("/cid"), "text/turtle", null);
        assertEquals(200, response.status());
        assertEquals("the controlled identifier document", response.body());
    }

    /**
     * P0-6. Keycloak's shared client happens to disable redirects by default, but that is a deployment
     * setting; the verifiers must not depend on it. A 302 is returned as a 302, not followed — and its
     * body is not read, since no verifier looks at anything but a 200.
     */
    @Test
    void neverFollowsARedirect() throws Exception {
        OutboundHttp.Fetched response = OutboundHttp.fetch(url("/redirect"), null, null);
        assertEquals(302, response.status(),
                "a redirect must surface as a 302, never be followed to a target the guard has not seen");
        assertNull(response.body());
    }

    /**
     * R-29. Dereferencing a subject follows a redirect — a WebID answering {@code 303 See Other}, the
     * httpRange-14 pattern, or http going to https — where {@link OutboundHttp#fetch} does not.
     */
    @Test
    void dereferencingASubjectFollowsRedirects() throws Exception {
        OutboundHttp.Fetched moved = OutboundHttp.dereference(url("/redirect"), null, null);
        assertEquals(200, moved.status());
        assertEquals("the redirect target", moved.body());
        OutboundHttp.Fetched seeOther = OutboundHttp.dereference(url("/see-other"), null, null);
        assertEquals(200, seeOther.status());
        assertEquals("the controlled identifier document", seeOther.body());
    }

    /** R-29. Three redirects and no more: the fourth answer is returned as it is. */
    @Test
    void dereferencingStopsAfterThreeRedirects() throws Exception {
        assertEquals(302, OutboundHttp.dereference(url("/loop"), null, null).status());
    }

    /** R-29. Every hop is vetted as the first request is: a redirect cannot reach what a URL could not. */
    @Test
    void eachRedirectIsVettedLikeTheFirstRequest() {
        SsrfGuard.BlockedException refused = assertThrows(SsrfGuard.BlockedException.class,
                () -> OutboundHttp.dereference(url("/to-unlisted"), null, null));
        assertFalse(refused instanceof SsrfGuard.InsecureSchemeException);
    }

    /**
     * P0-5. The guard is the resolver, so a host outside the allow-list cannot be reached even though
     * the very same server is reachable under its allow-listed name.
     */
    @Test
    void refusesAnInternalHostThatIsNotAllowListed() {
        // https, so it is the address that is refused rather than plain http to a host not allow-listed.
        SsrfGuard.BlockedException refused = assertThrows(SsrfGuard.BlockedException.class,
                () -> OutboundHttp.fetch("https://127.0.0.1:" + port + "/cid", null, null),
                "127.0.0.1 is not on the allow-list, so it must be refused even though localhost is");
        assertFalse(refused instanceof SsrfGuard.InsecureSchemeException);
    }

    /** R-07. Plain http still reaches an allow-listed host — the demos and the integration test need it. */
    @Test
    void plainHttpIsRefusedUnlessTheHostIsAllowListed() throws Exception {
        assertThrows(SsrfGuard.InsecureSchemeException.class,
                () -> OutboundHttp.fetch("http://127.0.0.1:" + port + "/cid", null, null));
        assertEquals(200, OutboundHttp.fetch(url("/elsewhere"), null, null).status());
    }

    @Test
    void aSmallBodyRoundTripsUnderTheCap() throws Exception {
        assertTrue(OutboundHttp.maxResponseBytes() > 0);
        assertEquals("the redirect target", OutboundHttp.fetch(url("/elsewhere"), null, null).body());
    }

    /**
     * R-01. A body that never ends is refused as soon as it passes the cap, and the connection is
     * aborted rather than drained: the server stops being read at once, instead of until it chooses to
     * stop (an earlier probe read 1.1 GB in 15 seconds with a two-second timeout).
     */
    @Test
    void anEndlessBodyIsCutOffAtTheCapNotDrained() throws Exception {
        long started = System.nanoTime();
        assertThrows(OutboundHttp.ResponseTooLargeException.class,
                () -> OutboundHttp.fetch(url("/endless"), null, null));
        long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
        assertTrue(elapsedMillis < DEADLINE_MILLIS,
                "the cap, not the deadline, must end it (took " + elapsedMillis + " ms)");
        Thread.sleep(300);
        long sent = endlessBytesSent.get();
        Thread.sleep(300);
        assertEquals(sent, endlessBytesSent.get(), "the server must not still be being read after the refusal");
        assertTrue(sent < 64L * 1024 * 1024, "only socket buffers' worth may have been sent, not " + sent);
    }

    /** R-01. A declared length over the cap is refused before any of the body is read. */
    @Test
    void aDeclaredLengthOverTheCapIsRefusedUpFront() {
        long started = System.nanoTime();
        assertThrows(OutboundHttp.ResponseTooLargeException.class,
                () -> OutboundHttp.fetch(url("/huge"), null, null));
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < DEADLINE_MILLIS,
                "nothing should have been waited for");
    }

    /**
     * R-01. Every read of the trickling body returns inside the read timeout, so only a deadline on the
     * whole exchange can end it.
     */
    @Test
    void aTricklingBodyIsAbortedAtTheDeadline() {
        assertAbortedAtTheDeadline("/trickle");
    }

    /** R-01. The deadline covers waiting for the response headers too, not only the body. */
    @Test
    void aServerThatNeverAnswersIsAbortedAtTheDeadline() {
        assertAbortedAtTheDeadline("/silent");
    }

    /**
     * R-01. One caller may have only its share of fetches in flight, so a caller pointing every request
     * at a slow server cannot hold the whole shared pool. A third concurrent fetch is refused at once,
     * not queued; once the first two finish the caller may fetch again.
     */
    @Test
    void aCallerMayHaveOnlyItsShareOfFetchesInFlight() throws Exception {
        ExecutorService callers = Executors.newFixedThreadPool(2);
        try {
            Future<?> first = callers.submit(() -> swallow(() -> OutboundHttp.fetch(url("/trickle"), null, null)));
            Future<?> second = callers.submit(() -> swallow(() -> OutboundHttp.fetch(url("/trickle"), null, null)));
            Thread.sleep(400); // both are now reading the trickle
            assertThrows(OutboundHttp.CallerBusyException.class,
                    () -> OutboundHttp.fetch(url("/cid"), null, null));
            first.get(5, TimeUnit.SECONDS);
            second.get(5, TimeUnit.SECONDS);
            assertEquals(200, OutboundHttp.fetch(url("/cid"), null, null).status(),
                    "the caller's slots must be released when its fetches end, however they end");
        } finally {
            callers.shutdownNow();
        }
    }

    /**
     * R-02. The path is the caller's choice, so nothing a path returns may count against the origin:
     * five credentials whose {@code sub} named a missing path on this server's own host used to stop
     * every hosted-WebID verification.
     */
    @Test
    void aMissingPathNeverTripsTheBreaker() throws Exception {
        for (int i = 0; i < 10; i++) {
            assertEquals(404, OutboundHttp.fetch(url("/missing"), null, null).status());
        }
        assertEquals(200, OutboundHttp.fetch(url("/cid"), null, null).status());
    }

    /** R-02. An origin that refuses connections is what the breaker is for. */
    @Test
    void anUnreachableOriginTripsTheBreaker() throws Exception {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            closedPort = socket.getLocalPort();
        }
        String unreachable = "http://localhost:" + closedPort + "/cid";
        for (int i = 0; i < 5; i++) {
            // Apache's HttpHostConnectException, a ConnectException
            assertThrows(ConnectException.class, () -> OutboundHttp.fetch(unreachable, null, null));
        }
        assertThrows(OutboundHttp.HostUnavailableException.class, () -> OutboundHttp.fetch(unreachable, null, null));
        assertEquals(200, OutboundHttp.fetch(url("/cid"), null, null).status(),
                "another port on the same host is another origin");
    }

    /**
     * R-44. The shared pool holds four connections per origin. A fetch that finds all four busy waits for
     * one no longer than the connection-request timeout and is then refused, rather than queueing until
     * its deadline; and since waiting for the pool is this server's load, not the origin's failure
     * (R-02), however often it happens it never trips the origin's breaker.
     */
    @Test
    void anExhaustedPoolIsWaitedForBrieflyAndNeverTripsTheBreaker() throws Exception {
        System.setProperty(TIMEOUT_PROPERTY, "300");
        System.setProperty(DEADLINE_PROPERTY, "5000");
        ServerSettings.contribute("test", null);
        ExecutorService holders = Executors.newFixedThreadPool(4);
        dripsStarted.set(0);
        dripsReleased = false;
        try {
            java.util.List<Future<?>> held = new java.util.ArrayList<>();
            for (int i = 0; i < 4; i++) {
                // Two callers with two fetches each: the per-caller bound is two, the per-origin pool four.
                KeycloakSession caller = callerAt("203.0.113." + (20 + i / 2));
                held.add(holders.submit(() -> swallow(() -> OutboundHttp.fetch(url("/drip"), null, caller))));
            }
            // Until the server has all four, each holding a pooled connection (a cold JVM is slow to start them).
            long waitUntil = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (dripsStarted.get() < 4 && System.nanoTime() < waitUntil) {
                Thread.sleep(10);
            }
            assertEquals(4, dripsStarted.get(), "the four holding fetches never all reached the server");

            // Six waits while the four still hold: had the first five counted against the origin, the sixth
            // would be refused by its open breaker instead of waiting for the pool. (Checking after the four
            // finish would prove nothing — an answer from the origin closes its breaker.)
            KeycloakSession third = callerAt("203.0.113.30");
            for (int i = 0; i < 6; i++) {
                long started = System.nanoTime();
                assertThrows(ConnectionPoolTimeoutException.class, () -> OutboundHttp.fetch(url("/cid"), null, third));
                long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
                assertTrue(elapsedMillis < 1_000,
                        "the wait for a pooled connection is the 300 ms timeout, not the deadline (took "
                                + elapsedMillis + " ms)");
            }
            dripsReleased = true;
            for (Future<?> holder : held) {
                holder.get(10, TimeUnit.SECONDS);
            }
            assertEquals(200, OutboundHttp.fetch(url("/cid"), null, third).status(),
                    "the pool and the callers' slots are free again once the four finish");
        } finally {
            dripsReleased = true;
            holders.shutdownNow();
            System.clearProperty(TIMEOUT_PROPERTY);
            System.setProperty(DEADLINE_PROPERTY, String.valueOf(DEADLINE_MILLIS));
            ServerSettings.contribute("test", null);
        }
    }

    /** A session whose caller is at {@code address}; it offers no providers, so the guarded client is used. */
    private static KeycloakSession callerAt(String address) {
        ClientConnection connection = (ClientConnection) Proxy.newProxyInstance(
                ClientConnection.class.getClassLoader(), new Class<?>[]{ClientConnection.class},
                (proxy, method, args) -> "getRemoteAddr".equals(method.getName()) ? address : null);
        KeycloakContext context = (KeycloakContext) Proxy.newProxyInstance(
                KeycloakContext.class.getClassLoader(), new Class<?>[]{KeycloakContext.class},
                (proxy, method, args) -> "getConnection".equals(method.getName()) ? connection : null);
        return (KeycloakSession) Proxy.newProxyInstance(
                KeycloakSession.class.getClassLoader(), new Class<?>[]{KeycloakSession.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getContext" -> context;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> null; // getProvider: no truststore, no session client
                });
    }

    private void assertAbortedAtTheDeadline(String path) {
        long started = System.nanoTime();
        IOException failure = assertThrows(IOException.class, () -> OutboundHttp.fetch(url(path), null, null));
        long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
        assertFalse(failure instanceof OutboundHttp.ResponseTooLargeException, "this is the deadline, not the cap");
        assertTrue(elapsedMillis >= DEADLINE_MILLIS - 100 && elapsedMillis < DEADLINE_MILLIS + 2_000,
                "expected an abort at about " + DEADLINE_MILLIS + " ms, took " + elapsedMillis + " ms");
    }

    private interface Fetch {
        void run() throws Exception;
    }

    private static void swallow(Fetch fetch) {
        try {
            fetch.run();
        } catch (Exception expected) {
            // the deadline ends it
        }
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }

    private int hitsOn(String path) {
        java.util.concurrent.atomic.AtomicInteger count = hits.get(path);
        return count == null ? 0 : count.get();
    }

    // ------------------------------------------------------------------------ the cache (R-26)

    /**
     * R-26. "Verifiers are encouraged to cache controlled identifier documents to reduce unnecessary
     * network requests and the associated metadata leakage." A fresh copy is used without asking again.
     */
    @Test
    void aDocumentIsFetchedOnceWhileItIsFresh() throws Exception {
        OutboundHttp.Fetched first = OutboundHttp.fetch(url("/counted"), "text/turtle", null);
        OutboundHttp.Fetched second = OutboundHttp.fetch(url("/counted"), "text/turtle", null);
        assertEquals(1, hitsOn("/counted"));
        assertFalse(first.cached());
        assertTrue(second.cached());
        assertEquals(first.body(), second.body());

        OutboundHttp.fetch(url("/counted"), "application/ld+json", null);
        assertEquals(2, hitsOn("/counted"), "another Accept may get another document");
        OutboundHttp.dereference(url("/counted"), "text/turtle", null);
        assertEquals(3, hitsOn("/counted"), "following redirects may get another document too");
    }

    /** What the server says about caching is honoured, and failures are always asked again. */
    @Test
    void theServerSaysHowLongAndFailuresAreNotKept() throws Exception {
        OutboundHttp.fetch(url("/no-store"), null, null);
        OutboundHttp.fetch(url("/no-store"), null, null);
        assertEquals(2, hitsOn("/no-store"));

        OutboundHttp.fetch(url("/missing-counted"), null, null);
        OutboundHttp.fetch(url("/missing-counted"), null, null);
        assertEquals(2, hitsOn("/missing-counted"));

        long[] now = {System.currentTimeMillis()};
        OutboundHttp.useClock(() -> now[0]);
        try {
            OutboundHttp.fetch(url("/max-age-5"), null, null);
            now[0] += 4_000;
            OutboundHttp.fetch(url("/max-age-5"), null, null);
            assertEquals(1, hitsOn("/max-age-5"));
            now[0] += 2_000;
            OutboundHttp.fetch(url("/max-age-5"), null, null);
            assertEquals(2, hitsOn("/max-age-5"), "max-age=5 is five seconds, not the five-minute ceiling");
        } finally {
            OutboundHttp.resetCircuits();
        }
    }

    /** {@code http-cache-seconds=0} turns caching off. */
    @Test
    void cachingCanBeTurnedOff() throws Exception {
        System.setProperty("lws.authn.http.cacheSeconds", "0");
        try {
            ServerSettings.contribute("test", null);
            int before = hitsOn("/counted");
            OutboundHttp.fetch(url("/counted"), "text/plain", null);
            OutboundHttp.fetch(url("/counted"), "text/plain", null);
            assertEquals(before + 2, hitsOn("/counted"));
        } finally {
            System.clearProperty("lws.authn.http.cacheSeconds");
            System.setProperty("lws.authn.http.cacheSeconds", "300");
            ServerSettings.contribute("test", null);
            System.clearProperty("lws.authn.http.cacheSeconds");
        }
    }

    /**
     * R-26. A JWT naming a key the cached JWK set lacks may mean the issuer has just rotated, so the
     * verifier may ask again — but not more than once in thirty seconds, or made-up kids would make every
     * token cost a fetch.
     */
    @Test
    void aRefetchIsRateLimited() throws Exception {
        long[] now = {System.currentTimeMillis()};
        OutboundHttp.useClock(() -> now[0]);
        try {
            OutboundHttp.fetch(url("/counted"), "application/json", null);
            int fetched = hitsOn("/counted");
            assertNull(OutboundHttp.refetch(url("/counted"), "application/json", null),
                    "the copy is seconds old: there is nothing new to find");
            now[0] += OutboundHttp.REFETCH_INTERVAL_MS + 1;
            OutboundHttp.Fetched fresh = OutboundHttp.refetch(url("/counted"), "application/json", null);
            assertEquals(200, fresh.status());
            assertFalse(fresh.cached());
            assertEquals(fetched + 1, hitsOn("/counted"));
            assertNull(OutboundHttp.refetch(url("/counted"), "application/json", null));
            assertTrue(OutboundHttp.fetch(url("/counted"), "application/json", null).cached(),
                    "what a refetch brings back is cached");
        } finally {
            OutboundHttp.resetCircuits();
        }
    }
}
