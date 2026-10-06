/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.net;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * The URL-level policy. The internal-address cases use {@code https} so they exercise the address check,
 * not the scheme check that would refuse a plain {@code http} URL to a host that is not allow-listed first.
 */
class SsrfGuardTest {

    private static final Set<String> NONE = Set.of();

    @Test
    void blocksLoopback() {
        assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("https://127.0.0.1:8080/admin", NONE));
    }

    @Test
    void blocksCloudMetadataLinkLocal() {
        assertThrows(SsrfGuard.BlockedException.class,
                () -> SsrfGuard.verify("https://169.254.169.254/latest/meta-data/", NONE));
    }

    @Test
    void blocksPrivateRanges() {
        for (String ip : new String[]{"10.1.2.3", "172.16.0.1", "192.168.1.1", "0.0.0.0"}) {
            assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("https://" + ip + "/", NONE),
                    "should block " + ip);
        }
    }

    @Test
    void blocksNonHttpScheme() {
        assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("file:///etc/passwd", NONE));
        assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("ftp://10.0.0.1/x", NONE));
    }

    @Test
    void allowsPublicAddress() {
        // literal public IPs — no DNS needed
        assertDoesNotThrow(() -> SsrfGuard.verify("https://8.8.8.8/", NONE));
        assertDoesNotThrow(() -> SsrfGuard.verify("https://93.184.216.34/", NONE));
    }

    @Test
    void allowlistPermitsConfiguredHost() {
        assertDoesNotThrow(() -> SsrfGuard.verify("http://localhost:8080/realms/x", Set.of("localhost")));
    }

    /**
     * R-07. Everything the verifiers fetch carries or locates a key, and over plain http anyone on the
     * network path can swap it. So http is refused — before any lookup — unless the deployment has
     * allow-listed the host.
     */
    @Test
    void refusesPlainHttpToAHostThatIsNotAllowListed() {
        assertThrows(SsrfGuard.InsecureSchemeException.class, () -> SsrfGuard.verify("http://8.8.8.8/", NONE));
        assertThrows(SsrfGuard.InsecureSchemeException.class,
                () -> SsrfGuard.verify("HTTP://93.184.216.34/cid", Set.of("localhost")));
        assertThrows(SsrfGuard.InsecureSchemeException.class,
                () -> SsrfGuard.verify("http://unresolvable.invalid/cid", NONE),
                "the scheme is refused before the name is looked up");
        assertDoesNotThrow(() -> SsrfGuard.verify("http://LOCALHOST:8080/x", Set.of("localhost")));
        assertDoesNotThrow(() -> SsrfGuard.verify("http://[::1]:8080/x", Set.of("::1")));
    }

    @Test
    void secureOrAllowListed() {
        assertTrue(SsrfGuard.secureOrAllowListed("https", "anything.example", NONE));
        assertTrue(SsrfGuard.secureOrAllowListed("HTTPS", "anything.example", NONE));
        assertFalse(SsrfGuard.secureOrAllowListed("http", "anything.example", NONE));
        assertTrue(SsrfGuard.secureOrAllowListed("http", "Kc.Internal", Set.of("kc.internal")));
        assertFalse(SsrfGuard.secureOrAllowListed("ftp", "kc.internal", Set.of("kc.internal")));
        assertFalse(SsrfGuard.secureOrAllowListed(null, "kc.internal", Set.of("kc.internal")));
        assertFalse(SsrfGuard.secureOrAllowListed("http", null, Set.of("kc.internal")));
    }

    @Test
    void blocksCarrierGradeNat() {
        for (String ip : new String[]{"100.64.0.1", "100.100.50.1", "100.127.255.255"}) {
            assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("https://" + ip + "/", NONE),
                    "should block CGNAT " + ip);
        }
    }

    @Test
    void blocksZeroNetwork() {
        assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("https://0.1.2.3/", NONE));
    }

    @Test
    void blocksIpv4MappedLoopback() {
        // An IPv4-mapped IPv6 loopback must be refused (whether the JDK normalizes it or it fails to resolve).
        assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("https://[::ffff:127.0.0.1]/", NONE));
    }

    @Test
    void allowsPublicAddressesNearCgnat() {
        // 100.63/8 and 100.128/9 lie outside 100.64.0.0/10 and must not be over-blocked
        assertDoesNotThrow(() -> SsrfGuard.verify("https://100.63.0.1/", NONE));
        assertDoesNotThrow(() -> SsrfGuard.verify("https://100.128.0.1/", NONE));
    }
}
