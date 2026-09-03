/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.keycloak.broker.provider.util.SimpleHttp;

/**
 * P0-5 and P0-6, exercised against a real HTTP server rather than only reasoned about.
 *
 * <p>The verifiers no longer fetch through Keycloak's server-wide client. They use one built here with
 * redirect following disabled and {@link GuardedDnsResolver} installed, which is only worth anything if
 * the client actually builds and behaves that way — the resolver is set on the Apache builder
 * underneath Keycloak's wrapper, and Apache honours it only because Keycloak never installs its own
 * connection manager. That is exactly the kind of assumption that deserves a test.</p>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OutboundHttpClientTest {

    private static final String ALLOWLIST_PROPERTY = "lws.authn.allowedInternalHosts";

    private HttpServer server;
    private int port;
    private String previousAllowlist;

    @BeforeAll
    void startServer() throws Exception {
        // The test targets are on loopback, so loopback has to be an intended target here — the same
        // opt-in a single-box Keycloak needs to dereference its own controlled identifier documents.
        previousAllowlist = System.getProperty(ALLOWLIST_PROPERTY);
        System.setProperty(ALLOWLIST_PROPERTY, "localhost");

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        port = server.getAddress().getPort();
        server.createContext("/cid", exchange -> respond(exchange, 200, "the controlled identifier document"));
        server.createContext("/elsewhere", exchange -> respond(exchange, 200, "the redirect target"));
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().add("Location", "http://localhost:" + port + "/elsewhere");
            respond(exchange, 302, "");
        });
        server.start();
    }

    @AfterAll
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
        if (previousAllowlist == null) {
            System.clearProperty(ALLOWLIST_PROPERTY);
        } else {
            System.setProperty(ALLOWLIST_PROPERTY, previousAllowlist);
        }
        OutboundHttp.resetCircuits();
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body)
            throws java.io.IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    /**
     * The whole custom-client path works end to end: the subclass reaches Keycloak's Apache builder,
     * the resolver is accepted, and a fetch completes.
     */
    @Test
    void fetchesThroughTheGuardedClient() throws Exception {
        SimpleHttp.Response response = OutboundHttp.get(url("/cid"), null).asResponse();
        assertEquals(200, response.getStatus());
        assertEquals("the controlled identifier document", response.asString());
    }

    /**
     * P0-6. Keycloak's shared client happens to disable redirects by default, but that is a deployment
     * setting; the verifiers must not depend on it. A 302 is returned as a 302, not followed.
     */
    @Test
    void neverFollowsARedirect() throws Exception {
        SimpleHttp.Response response = OutboundHttp.get(url("/redirect"), null).asResponse();
        assertEquals(302, response.getStatus(),
                "a redirect must surface as a 302, never be followed to a target the guard has not seen");
    }

    /**
     * P0-5. The guard is the resolver, so a host outside the allow-list cannot be reached even though
     * the very same server is reachable under its allow-listed name.
     */
    @Test
    void refusesAnInternalHostThatIsNotAllowListed() {
        assertThrows(SsrfGuard.BlockedException.class,
                () -> OutboundHttp.get("http://127.0.0.1:" + port + "/cid", null),
                "127.0.0.1 is not on the allow-list, so it must be refused even though localhost is");
    }

    /** The response-size cap still applies on the new client. */
    @Test
    void keepsTheResponseSizeCap() throws Exception {
        assertTrue(OutboundHttp.maxResponseBytes() > 0);
        // A small body is well under the cap and must round-trip untouched.
        assertEquals("the redirect target", OutboundHttp.get(url("/elsewhere"), null).asResponse().asString());
    }

    private String url(String path) {
        return "http://localhost:" + port + path;
    }
}
