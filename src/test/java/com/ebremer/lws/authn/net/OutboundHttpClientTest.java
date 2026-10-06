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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

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
    private static final long DEADLINE_MILLIS = 1_500;

    private HttpServer server;
    private ExecutorService handlers;
    private int port;
    private String previousAllowlist;
    private final AtomicLong endlessBytesSent = new AtomicLong();

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

    @AfterEach
    void forgetFailures() {
        OutboundHttp.resetCircuits();
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
}
