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

    private static void assertBlocked(String literal) {
        String host = literal.contains(":") ? "[" + literal + "]" : literal;
        assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("https://" + host + "/", NONE),
                "should block " + literal);
    }

    private static void assertAllowed(String literal) {
        String host = literal.contains(":") ? "[" + literal + "]" : literal;
        assertDoesNotThrow(() -> SsrfGuard.verify("https://" + host + "/", NONE), "should allow " + literal);
    }

    /**
     * R-08. IPv6 formats that carry an IPv4 address are judged by that address. NAT64 is the one that
     * matters in practice: on an IPv6-only subnet with DNS64, {@code 64:ff9b::a9fe:a9fe} is
     * 169.254.169.254.
     */
    @Test
    void judgesAnEmbeddedIpv4AddressByItself() {
        assertBlocked("64:ff9b::a9fe:a9fe");       // NAT64 → 169.254.169.254
        assertBlocked("64:ff9b::7f00:1");          // NAT64 → 127.0.0.1
        assertBlocked("64:ff9b::a00:1");           // NAT64 → 10.0.0.1
        assertBlocked("2002:a9fe:a9fe::1");        // 6to4 → 169.254.169.254
        assertBlocked("2002:c0a8:101::1");         // 6to4 → 192.168.1.1
        assertAllowed("64:ff9b::808:808");         // NAT64 → 8.8.8.8
        assertAllowed("2002:808:808::1");          // 6to4 → 8.8.8.8
    }

    /** R-08. Outside global unicast, or in a block of it that is not globally reachable. */
    @Test
    void blocksIpv6ThatIsNotGlobalUnicast() {
        for (String literal : new String[]{
                "::127.0.0.1", "::8.8.8.8",              // IPv4-compatible, deprecated
                "::ffff:0:a9fe:a9fe",                    // SIIT
                "64:ff9b:1::a9fe:a9fe",                  // local-use NAT64
                "100::1",                                // discard-only
                "2001::1", "2001:0:4136:e378::1",        // Teredo
                "2001:2::1",                             // benchmarking
                "2001:db8::1", "3fff::1",                // documentation
                "5f00::1",                               // SRv6
                "fc00::1", "fd12:3456::1",               // unique-local
                "fe80::1", "fec0::1",                    // link-local, old site-local
                "ff02::1", "::", "::1"}) {
            assertBlocked(literal);
        }
    }

    /** R-08. The IPv4 special-purpose blocks the JDK's predicates miss. */
    @Test
    void blocksIpv4SpecialPurposeRanges() {
        for (String literal : new String[]{"192.0.0.1", "192.0.0.170", "192.0.2.1", "192.88.99.1",
                "198.18.0.1", "198.19.255.255", "198.51.100.1", "203.0.113.1", "240.0.0.1", "255.255.255.255"}) {
            assertBlocked(literal);
        }
    }

    /** And nothing global is caught by the blocks either side of it. */
    @Test
    void allowsGlobalAddressesNextToTheBlocks() {
        for (String literal : new String[]{"8.8.8.8", "1.1.1.1", "192.0.1.1", "192.0.3.1", "198.17.255.255",
                "198.20.0.1", "203.0.114.1", "223.255.255.254", "192.31.196.1",
                "2606:4700:4700::1111", "2001:4860:4860::8888", "2001:200::1", "2a00:1450:4001::1"}) {
            assertAllowed(literal);
        }
    }
}
