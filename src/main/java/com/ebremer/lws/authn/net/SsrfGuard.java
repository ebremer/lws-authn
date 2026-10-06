/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * SSRF guard for outbound HTTP fetches driven by attacker-influenced URLs (the OpenID and self-signed
 * CID verifiers dereference the credential's `sub`/`iss`). Only https is allowed — plain http only to an
 * allow-listed host — and the target host must not resolve to a loopback / private / link-local /
 * reserved address unless it is explicitly allow-listed.
 */
package com.ebremer.lws.authn.net;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;

import com.ebremer.lws.authn.config.ServerSettings;

/**
 * Validates a URL before it is fetched, to prevent Server-Side Request Forgery.
 *
 * <p>An allow-list (comma-separated hostnames) lets a deployment permit legitimate internal targets —
 * for example a Keycloak that hosts its own controlled identifier documents on a loopback or internal
 * address. It comes from {@link ServerSettings#allowedInternalHosts()}: the provider configuration key
 * {@code allowed-internal-hosts}, the system property {@code lws.authn.allowedInternalHosts}, or the
 * environment variable {@code LWS_AUTHN_ALLOWED_INTERNAL_HOSTS}. By default nothing internal is
 * reachable.</p>
 *
 * <p>{@link #verify(String)} is the early, informative check: it requires https — plain http only to an
 * allow-listed host — and rejects a URL whose host resolves anywhere internal, so the caller gets a
 * useful error. For the scheme it is also the enforcement point, since the client follows no redirects;
 * for the address it is <em>not</em> — a name can resolve differently between that check and the moment
 * a socket is opened (DNS rebinding). Enforcement lives in {@link #resolveAndVet}, which
 * {@link GuardedDnsResolver} installs as the DNS resolver of the HTTP client
 * {@link OutboundHttp} uses, so the addresses that are vetted are exactly the addresses that are
 * connected to.</p>
 *
 * @author Erich Bremer
 */
public final class SsrfGuard {

    private SsrfGuard() {
    }

    /** Thrown when a URL must not be fetched. */
    public static class BlockedException extends RuntimeException {
        public BlockedException(String message) {
            super(message);
        }
    }

    /**
     * Thrown when a URL is plain {@code http} and its host is not allow-listed (R-07). Everything the
     * verifiers fetch carries or locates a key — the subject's document, the issuer's configuration, its
     * JWK set — and over plain http anyone on the network path can substitute that key. OpenID Connect
     * Core §2 requires {@code iss} to use https, Discovery §3 requires it of {@code jwks_uri}, and the
     * self-signed CID suite speaks of HTTPS subjects. The message names only what the caller sent.
     */
    public static final class InsecureSchemeException extends BlockedException {
        public InsecureSchemeException(String message) {
            super(message);
        }
    }

    /** Validates {@code url} against the configured allow-list; throws {@link BlockedException} if blocked. */
    public static void verify(String url) {
        verify(url, configuredAllowlist());
    }

    /** Validates {@code url} against an explicit allow-list of host names. */
    public static void verify(String url, Set<String> allowedHosts) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (Exception e) {
            throw new BlockedException("malformed URL: " + url);
        }
        String scheme = uri.getScheme();
        boolean https = "https".equalsIgnoreCase(scheme);
        if (!https && !"http".equalsIgnoreCase(scheme)) {
            throw new BlockedException("only https URLs may be fetched, got scheme: " + scheme);
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new BlockedException("URL has no host: " + url);
        }
        if (!https && !isAllowListed(host, allowedHosts)) {
            throw new InsecureSchemeException("plain http is fetched only from an allow-listed host, not from "
                    + host);
        }
        try {
            resolveAndVet(host, allowedHosts);
        } catch (UnknownHostException e) {
            throw new BlockedException(e.getMessage());
        }
    }

    /**
     * True iff a URL of this scheme and host may carry key material: {@code https}, or {@code http} to an
     * allow-listed host (R-07). An allow-listed host is one the deployment vouches for — its own Keycloak
     * on loopback, a test fixture — and so the one place plain http is still accepted.
     */
    public static boolean secureOrAllowListed(String scheme, String host, Set<String> allowedHosts) {
        if ("https".equalsIgnoreCase(scheme)) {
            return true;
        }
        return "http".equalsIgnoreCase(scheme) && host != null && isAllowListed(host, allowedHosts);
    }

    private static boolean isAllowListed(String host, Set<String> allowedHosts) {
        String normalized = normalizeHost(host);
        return allowedHosts.contains(normalized)
                || allowedHosts.stream().anyMatch(entry -> normalizeHost(entry).equals(normalized));
    }

    /**
     * {@code host} in the one spelling the allow-list is kept in (R-35): trimmed and lower-cased, without
     * the brackets of an IPv6 literal or the trailing dot of a fully qualified name, and an IPv6 literal
     * in its full form. An allow-list entry written {@code [::1]} or {@code kc.internal.} used to match
     * nothing — failing closed, but with no way to tell why.
     */
    public static String normalizeHost(String host) {
        String h = normalize(host).toLowerCase(Locale.ROOT);
        if (h.endsWith(".") && h.length() > 1) {
            h = h.substring(0, h.length() - 1);
        }
        if (h.indexOf(':') >= 0 && h.matches("[0-9a-f:.]+")) {
            try {
                // A literal, which InetAddress parses without asking DNS: "::1" and "0:0:0:0:0:0:0:1" alike.
                h = InetAddress.getByName(h).getHostAddress();
            } catch (UnknownHostException notALiteral) {
                // left as written; it will match only itself
            }
        }
        return h;
    }

    /**
     * Resolves {@code host} and returns its addresses, having checked every one of them against the
     * internal-address policy. This is the enforcement point: the caller connects to exactly the
     * addresses returned here, so the name is never resolved a second time and cannot change under the
     * check.
     *
     * <p>An allow-listed host is still resolved — the addresses are needed to connect — but is not
     * subjected to the internal-address check.</p>
     *
     * @throws UnknownHostException if the name does not resolve, or resolves to an address this
     *         deployment must not reach. The message deliberately names only the host, never the
     *         resolved address, because it can surface in a client-facing error.
     */
    public static InetAddress[] resolveAndVet(String host) throws UnknownHostException {
        return resolveAndVet(host, configuredAllowlist());
    }

    /** As {@link #resolveAndVet(String)}, against an explicit allow-list of host names. */
    public static InetAddress[] resolveAndVet(String host, Set<String> allowedHosts) throws UnknownHostException {
        if (host == null || host.isBlank()) {
            throw new UnknownHostException("no host to resolve");
        }
        String name = normalize(host);
        InetAddress[] addresses = InetAddress.getAllByName(name);
        if (addresses.length == 0) {
            throw new UnknownHostException("cannot resolve host: " + name);
        }
        if (isAllowListed(name, allowedHosts)) {
            return addresses;
        }
        for (InetAddress address : addresses) {
            if (isInternal(address)) {
                throw new UnknownHostException("refusing to fetch an internal address for host '" + name
                        + "' (allow it via lws.authn.allowedInternalHosts if intended)");
            }
        }
        return addresses;
    }

    /**
     * Strips the brackets from an IPv6 literal. {@link URI#getHost()} keeps them ({@code [::1]}) while
     * Apache HttpClient hands the resolver the bare form, so both spellings must key the same host.
     */
    private static String normalize(String host) {
        String h = host.trim();
        if (h.length() > 1 && h.charAt(0) == '[' && h.charAt(h.length() - 1) == ']') {
            return h.substring(1, h.length() - 1);
        }
        return h;
    }

    /**
     * True unless {@code a} is a globally reachable unicast address (R-08).
     *
     * <p>IPv6 is decided by what is allowed rather than what is not: only global unicast,
     * {@code 2000::/3}, less the blocks the IANA IPv6 Special-Purpose Address Registry marks as not
     * globally reachable. That excludes in one stroke everything below it — loopback, unspecified, the
     * deprecated IPv4-compatible {@code ::a.b.c.d}, SIIT's {@code ::ffff:0:a.b.c.d}, discard-only
     * {@code 100::/64}, local-use NAT64 {@code 64:ff9b:1::/48}, unique-local, link-local, multicast.
     * Three formats carry an IPv4 address the packet is really bound for, and are judged by that address
     * instead: IPv4-mapped {@code ::ffff:a.b.c.d}, well-known NAT64 {@code 64:ff9b::/96} — real on
     * IPv6-only cloud subnets with DNS64, where {@code 64:ff9b::a9fe:a9fe} reaches 169.254.169.254 — and
     * 6to4 {@code 2002::/16}. Teredo ({@code 2001::/32}) obscures its address, and falls in a
     * not-reachable block anyway.</p>
     *
     * <p>IPv4 is decided by the IANA IPv4 Special-Purpose Address Registry's not-globally-reachable
     * blocks, which the JDK's own predicates only partly cover.</p>
     */
    static boolean isInternal(InetAddress a) {
        if (a.isLoopbackAddress() || a.isAnyLocalAddress() || a.isLinkLocalAddress()
                || a.isSiteLocalAddress() || a.isMulticastAddress()) {
            return true; // what the JDK already knows; the tables below are the rule
        }
        byte[] b = a.getAddress();
        if (b.length == 4) {
            return isInternalIpv4(b);
        }
        if (isIpv4Mapped(b) || NAT64.contains(b)) {
            return isInternalIpv4(Arrays.copyOfRange(b, 12, 16));
        }
        if (SIX_TO_FOUR.contains(b)) {
            return isInternalIpv4(Arrays.copyOfRange(b, 2, 6));
        }
        if (!IPV6_GLOBAL_UNICAST.contains(b)) {
            return true;
        }
        for (Block block : IPV6_NOT_GLOBAL) {
            if (block.contains(b)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isInternalIpv4(byte[] b) {
        for (Block block : IPV4_NOT_GLOBAL) {
            if (block.contains(b)) {
                return true;
            }
        }
        return false;
    }

    /** True for an IPv4-mapped IPv6 address (::ffff:a.b.c.d): 80 zero bits then 0xffff. */
    private static boolean isIpv4Mapped(byte[] b) {
        for (int i = 0; i < 10; i++) {
            if (b[i] != 0) {
                return false;
            }
        }
        return (b[10] & 0xFF) == 0xFF && (b[11] & 0xFF) == 0xFF;
    }

    /**
     * IPv4 blocks that are not globally reachable (IANA IPv4 Special-Purpose Address Registry, plus
     * multicast and the deprecated 6to4 relay anycast). The few globally reachable anycast addresses
     * inside {@code 192.0.0.0/24} are refused with it: nothing a verifier fetches lives there.
     */
    private static final Block[] IPV4_NOT_GLOBAL = {
        Block.of("0.0.0.0/8"),          // "this network"
        Block.of("10.0.0.0/8"),         // private
        Block.of("100.64.0.0/10"),      // carrier-grade NAT
        Block.of("127.0.0.0/8"),        // loopback
        Block.of("169.254.0.0/16"),     // link-local, including cloud metadata
        Block.of("172.16.0.0/12"),      // private
        Block.of("192.0.0.0/24"),       // IETF protocol assignments, DS-Lite, NAT64 discovery
        Block.of("192.0.2.0/24"),       // documentation
        Block.of("192.88.99.0/24"),     // 6to4 relay anycast, deprecated
        Block.of("192.168.0.0/16"),     // private
        Block.of("198.18.0.0/15"),      // benchmarking
        Block.of("198.51.100.0/24"),    // documentation
        Block.of("203.0.113.0/24"),     // documentation
        Block.of("224.0.0.0/4"),        // multicast
        Block.of("240.0.0.0/4"),        // reserved, and the limited broadcast address
    };

    private static final Block IPV6_GLOBAL_UNICAST = Block.of("2000::/3");
    private static final Block NAT64 = Block.of("64:ff9b::/96");
    private static final Block SIX_TO_FOUR = Block.of("2002::/16");

    /** Blocks inside {@code 2000::/3} that are not globally reachable (IANA IPv6 Special-Purpose Registry). */
    private static final Block[] IPV6_NOT_GLOBAL = {
        Block.of("2001::/23"),          // IETF protocol assignments: Teredo, benchmarking, ORCHID, …
        Block.of("2001:db8::/32"),      // documentation
        Block.of("3fff::/20"),          // documentation
        Block.of("5f00::/16"),          // SRv6 segment identifiers
    };

    /** An address block: a prefix and its length in bits. */
    private record Block(byte[] prefix, int bits) {

        /** Parses {@code address/bits}; the address is a literal, so nothing is looked up. */
        static Block of(String cidr) {
            int slash = cidr.indexOf('/');
            try {
                byte[] prefix = InetAddress.getByName(cidr.substring(0, slash)).getAddress();
                return new Block(prefix, Integer.parseInt(cidr.substring(slash + 1)));
            } catch (UnknownHostException e) {
                throw new IllegalArgumentException(cidr, e);
            }
        }

        boolean contains(byte[] address) {
            if (address.length != prefix.length) {
                return false;
            }
            int whole = bits / 8;
            for (int i = 0; i < whole; i++) {
                if (address[i] != prefix[i]) {
                    return false;
                }
            }
            int rest = bits % 8;
            if (rest == 0) {
                return true;
            }
            int mask = (0xFF << (8 - rest)) & 0xFF;
            return (address[whole] & mask) == (prefix[whole] & mask);
        }
    }

    /** The configured allow-list of internal host names. */
    public static Set<String> configuredAllowlist() {
        return ServerSettings.allowedInternalHosts();
    }
}
