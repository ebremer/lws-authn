/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.net;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * P0-3. A verify request makes this server spend five seconds per outbound fetch on a target the
 * caller chose. Once a host has failed repeatedly there is no reason to keep paying that, so its
 * breaker opens and the next request is refused without a fetch.
 */
class OutboundHttpCircuitTest {

    private static final String URL = "https://cid.example/agent";

    @BeforeEach
    @AfterEach
    void reset() {
        OutboundHttp.resetCircuits();
    }

    @Test
    void opensAfterRepeatedFailuresAgainstTheSameHost() {
        for (int i = 0; i < 5; i++) {
            OutboundHttp.recordFailure(URL);
        }
        assertThrows(OutboundHttp.HostUnavailableException.class,
                () -> OutboundHttp.get(URL, null),
                "a host that just failed five times must not be fetched again immediately");
    }

    @Test
    void staysClosedBelowTheThreshold() {
        for (int i = 0; i < 4; i++) {
            OutboundHttp.recordFailure(URL);
        }
        // Four failures are not enough to open it. The call still fails, but on the SSRF check
        // (cid.example does not resolve) rather than on the breaker.
        assertThrows(SsrfGuard.BlockedException.class, () -> OutboundHttp.get(URL, null));
    }

    @Test
    void aSuccessClearsTheHistory() {
        for (int i = 0; i < 5; i++) {
            OutboundHttp.recordFailure(URL);
        }
        OutboundHttp.recordSuccess(URL);
        assertThrows(SsrfGuard.BlockedException.class, () -> OutboundHttp.get(URL, null),
                "after a success the breaker must be closed again");
    }

    /** One host's failures must not short-circuit another's. */
    @Test
    void breakersArePerHost() {
        for (int i = 0; i < 5; i++) {
            OutboundHttp.recordFailure(URL);
        }
        assertThrows(SsrfGuard.BlockedException.class,
                () -> OutboundHttp.get("https://other.example/agent", null));
    }

    @Test
    void unparseableUrlsAreIgnoredRatherThanTracked() {
        assertDoesNotThrow(() -> OutboundHttp.recordFailure("not a url"));
        assertDoesNotThrow(() -> OutboundHttp.recordSuccess(null));
    }
}
