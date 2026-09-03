package com.ebremer.lws.authn.net;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * P0-5. Checking a URL and then letting the HTTP stack resolve the name a second time leaves a
 * time-of-check/time-of-use gap that a hostile name server closes on its own terms. Making the SSRF
 * check part of resolution removes the second lookup: whatever the guard approves is exactly what the
 * connection manager connects to.
 */
class GuardedDnsResolverTest {

    private static final Set<String> NONE = Set.of();

    @Test
    void resolutionIsWhereTheCheckHappens() throws Exception {
        // The resolver is the enforcement point, so it must refuse an internal answer itself rather
        // than trusting an earlier check on the URL.
        assertThrows(UnknownHostException.class, () -> SsrfGuard.resolveAndVet("127.0.0.1", NONE));
        assertThrows(UnknownHostException.class, () -> SsrfGuard.resolveAndVet("169.254.169.254", NONE));

        InetAddress[] resolved = new GuardedDnsResolver().resolve("8.8.8.8");
        assertNotNull(resolved);
        assertTrue(resolved.length > 0, "a public host must still resolve");
    }

    @Test
    void returnsTheVettedAddressesSoThereIsNoSecondLookup() throws Exception {
        InetAddress[] addresses = SsrfGuard.resolveAndVet("8.8.8.8", NONE);
        assertTrue(addresses.length > 0);
        for (InetAddress address : addresses) {
            assertTrue(!address.isLoopbackAddress() && !address.isSiteLocalAddress(),
                    "every returned address must already have passed the policy: " + address);
        }
    }

    @Test
    void anAllowListedHostStillResolvesSoItCanBeConnectedTo() throws Exception {
        InetAddress[] addresses = SsrfGuard.resolveAndVet("localhost", Set.of("localhost"));
        assertTrue(addresses.length > 0,
                "an intentionally allowed internal target must come back with addresses, not just a pass");
    }

    /** {@link java.net.URI#getHost()} keeps IPv6 brackets; the resolver is handed the bare form. */
    @Test
    void bracketedAndBareIpv6LiteralsAreTheSameHost() {
        assertThrows(UnknownHostException.class, () -> SsrfGuard.resolveAndVet("[::1]", NONE));
        assertThrows(UnknownHostException.class, () -> SsrfGuard.resolveAndVet("::1", NONE));
    }

    /** {@link SsrfGuard#verify} stays the early, friendly check in front of the resolver. */
    @Test
    void urlLevelCheckStillRejectsBeforeAnyFetch() {
        assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("http://10.1.2.3/x", NONE));
        assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("file:///etc/passwd", NONE));
    }
}
