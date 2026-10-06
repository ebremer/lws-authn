/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.net;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.SSLHandshakeException;

import org.apache.http.conn.ConnectTimeoutException;
import org.apache.http.conn.ConnectionPoolTimeoutException;
import org.apache.http.impl.execchain.RequestAbortedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The per-origin circuit breaker (P0-3, reworked by R-02).
 *
 * <p>A verify request makes this server fetch from an origin the caller chose. Once an origin cannot
 * be reached at all there is no reason to keep paying a connect timeout for it, so its breaker opens and
 * the next request is refused without a fetch. What R-02 changed is <em>what counts</em>: only failures
 * no path on the origin can produce, so a caller cannot trip the breaker against a healthy origin by
 * asking it for something that does not exist — and <em>what extends it</em>: nothing, once open.</p>
 */
class OutboundHttpCircuitTest {

    private static final String URL = "https://cid.example/agent";

    private final AtomicLong now = new AtomicLong(1_000_000L);

    @BeforeEach
    void reset() {
        OutboundHttp.resetCircuits();
        OutboundHttp.useClock(now::get);
    }

    @AfterEach
    void restore() {
        OutboundHttp.resetCircuits();
    }

    private static void failFiveTimes(String url) {
        for (int i = 0; i < 5; i++) {
            OutboundHttp.recordFailure(url);
        }
    }

    @Test
    void opensAfterRepeatedFailuresAgainstTheSameOrigin() {
        failFiveTimes(URL);
        assertThrows(OutboundHttp.HostUnavailableException.class,
                () -> OutboundHttp.fetch(URL, null, null),
                "an origin that just failed five times must not be fetched again immediately");
    }

    @Test
    void staysClosedBelowTheThreshold() {
        for (int i = 0; i < 4; i++) {
            OutboundHttp.recordFailure(URL);
        }
        // Four failures are not enough to open it. The call still fails, but on the SSRF check
        // (cid.example does not resolve) rather than on the breaker.
        assertThrows(SsrfGuard.BlockedException.class, () -> OutboundHttp.fetch(URL, null, null));
    }

    @Test
    void aSuccessClearsTheHistory() {
        failFiveTimes(URL);
        OutboundHttp.recordSuccess(URL);
        assertThrows(SsrfGuard.BlockedException.class, () -> OutboundHttp.fetch(URL, null, null),
                "after a success the breaker must be closed again");
    }

    /** R-02. Keyed on the origin: another host, scheme or port is a different breaker. */
    @Test
    void breakersArePerOrigin() {
        failFiveTimes(URL);
        assertThrows(SsrfGuard.BlockedException.class,
                () -> OutboundHttp.fetch("https://other.example/agent", null, null));
        assertThrows(SsrfGuard.BlockedException.class,
                () -> OutboundHttp.fetch("http://cid.example/agent", null, null));
        assertThrows(SsrfGuard.BlockedException.class,
                () -> OutboundHttp.fetch("https://cid.example:8443/agent", null, null));
        assertThrows(OutboundHttp.HostUnavailableException.class,
                () -> OutboundHttp.fetch("https://CID.example:443/someone-else", null, null),
                "the same origin under another spelling, and another path on it, is the same breaker");
    }

    /**
     * R-02. Refusals do not extend an open breaker. It used to: the verifier's catch-all recorded the
     * breaker's own refusal as one more failure, so an origin stayed refused for as long as anyone kept
     * asking for it at least every ten seconds.
     */
    @Test
    void anOpenBreakerClosesOnScheduleHoweverOftenItIsAsked() {
        failFiveTimes(URL);
        for (int i = 0; i < 9; i++) {
            now.addAndGet(1_000);
            assertThrows(OutboundHttp.HostUnavailableException.class, () -> OutboundHttp.fetch(URL, null, null));
        }
        now.addAndGet(1_001);
        assertThrows(SsrfGuard.BlockedException.class, () -> OutboundHttp.fetch(URL, null, null),
                "ten seconds after it opened, the breaker must let a fetch through again");
    }

    /** R-02. A failure from a fetch already in flight when the breaker opened does not extend it either. */
    @Test
    void aLateFailureDoesNotExtendAnOpenBreaker() {
        failFiveTimes(URL);
        now.addAndGet(9_000);
        OutboundHttp.recordFailure(URL);
        now.addAndGet(1_001);
        assertThrows(SsrfGuard.BlockedException.class, () -> OutboundHttp.fetch(URL, null, null));
    }

    /** Failures that are not close together are forgotten rather than accumulated. */
    @Test
    void failuresFarApartDoNotAccumulate() {
        for (int i = 0; i < 10; i++) {
            OutboundHttp.recordFailure(URL);
            now.addAndGet(10_001);
        }
        assertThrows(SsrfGuard.BlockedException.class, () -> OutboundHttp.fetch(URL, null, null));
    }

    /**
     * R-02. Only failures that say the origin cannot be reached count. Anything that depends on the path
     * — which the caller chose — or on this server's own load does not.
     */
    @Test
    void onlyUnreachabilityCounts() {
        assertTrue(OutboundHttp.isOriginFailure(new ConnectException("Connection refused")));
        assertTrue(OutboundHttp.isOriginFailure(new ConnectTimeoutException("connect timed out")));
        assertTrue(OutboundHttp.isOriginFailure(new UnknownHostException("no such host")));
        assertTrue(OutboundHttp.isOriginFailure(new SSLHandshakeException("bad certificate")));

        assertFalse(OutboundHttp.isOriginFailure(new SocketTimeoutException("Read timed out")),
                "a slow response is a property of the path, and the deadline already bounds it");
        assertFalse(OutboundHttp.isOriginFailure(new RequestAbortedException("deadline")));
        assertFalse(OutboundHttp.isOriginFailure(new OutboundHttp.ResponseTooLargeException("too big")));
        assertFalse(OutboundHttp.isOriginFailure(new ConnectionPoolTimeoutException("pool exhausted")),
                "waiting for a pooled connection is about this server's load, not the origin");
    }

    @Test
    void originsAreSchemeHostAndPort() {
        assertEquals("https://cid.example:443", OutboundHttp.originOf("https://CID.example/agent#me"));
        assertEquals("http://cid.example:80", OutboundHttp.originOf("http://cid.example"));
        assertEquals("https://cid.example:8443", OutboundHttp.originOf("https://cid.example:8443/x?y"));
        assertNull(OutboundHttp.originOf("not a url"));
        assertNull(OutboundHttp.originOf("did:key:z6Mk"));
    }

    @Test
    void unparseableUrlsAreIgnoredRatherThanTracked() {
        assertDoesNotThrow(() -> OutboundHttp.recordFailure("not a url"));
        assertDoesNotThrow(() -> OutboundHttp.recordSuccess(null));
    }
}
