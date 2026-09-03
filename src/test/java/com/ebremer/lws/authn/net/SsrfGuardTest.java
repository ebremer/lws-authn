/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.net;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Set;

import org.junit.jupiter.api.Test;

class SsrfGuardTest {

    private static final Set<String> NONE = Set.of();

    @Test
    void blocksLoopback() {
        assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("http://127.0.0.1:8080/admin", NONE));
    }

    @Test
    void blocksCloudMetadataLinkLocal() {
        assertThrows(SsrfGuard.BlockedException.class,
                () -> SsrfGuard.verify("http://169.254.169.254/latest/meta-data/", NONE));
    }

    @Test
    void blocksPrivateRanges() {
        for (String ip : new String[]{"10.1.2.3", "172.16.0.1", "192.168.1.1", "0.0.0.0"}) {
            assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("http://" + ip + "/", NONE),
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

    @Test
    void blocksCarrierGradeNat() {
        for (String ip : new String[]{"100.64.0.1", "100.100.50.1", "100.127.255.255"}) {
            assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("http://" + ip + "/", NONE),
                    "should block CGNAT " + ip);
        }
    }

    @Test
    void blocksZeroNetwork() {
        assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("http://0.1.2.3/", NONE));
    }

    @Test
    void blocksIpv4MappedLoopback() {
        // An IPv4-mapped IPv6 loopback must be refused (whether the JDK normalizes it or it fails to resolve).
        assertThrows(SsrfGuard.BlockedException.class, () -> SsrfGuard.verify("http://[::ffff:127.0.0.1]/", NONE));
    }

    @Test
    void allowsPublicAddressesNearCgnat() {
        // 100.63/8 and 100.128/9 lie outside 100.64.0.0/10 and must not be over-blocked
        assertDoesNotThrow(() -> SsrfGuard.verify("https://100.63.0.1/", NONE));
        assertDoesNotThrow(() -> SsrfGuard.verify("https://100.128.0.1/", NONE));
    }
}
