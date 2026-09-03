/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * SSRF guard for outbound HTTP fetches driven by attacker-influenced URLs (the OpenID and self-signed
 * CID verifiers dereference the credential's `sub`/`iss`). Only http(s) is allowed, and the target
 * host must not resolve to a loopback / private / link-local / reserved address unless it is
 * explicitly allow-listed.
 */
package com.ebremer.lws.authn.net;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Validates a URL before it is fetched, to prevent Server-Side Request Forgery.
 *
 * <p>An allow-list (comma-separated hostnames) lets a deployment permit legitimate internal targets —
 * for example a Keycloak that hosts its own controlled identifier documents on a loopback or internal
 * address. It is read from the system property {@code lws.authn.allowedInternalHosts} or the
 * environment variable {@code LWS_AUTHN_ALLOWED_INTERNAL_HOSTS}. By default nothing internal is
 * reachable.</p>
 *
 * <p>{@link #verify(String)} is the early, informative check: it validates the scheme and rejects a
 * URL whose host resolves anywhere internal, so the caller gets a useful error. It is <em>not</em> the
 * enforcement point — a name can resolve differently between that check and the moment a socket is
 * opened (DNS rebinding). Enforcement lives in {@link #resolveAndVet}, which
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
    public static final class BlockedException extends RuntimeException {
        public BlockedException(String message) {
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
        if (scheme == null || !(scheme.equalsIgnoreCase("https") || scheme.equalsIgnoreCase("http"))) {
            throw new BlockedException("only http(s) URLs may be fetched, got scheme: " + scheme);
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new BlockedException("URL has no host: " + url);
        }
        try {
            resolveAndVet(host, allowedHosts);
        } catch (UnknownHostException e) {
            throw new BlockedException(e.getMessage());
        }
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
        if (allowedHosts.contains(name.toLowerCase(Locale.ROOT))) {
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

    private static boolean isInternal(InetAddress a) {
        byte[] b = a.getAddress();
        // Unwrap an IPv4-mapped IPv6 address (::ffff:a.b.c.d) and re-check its embedded IPv4, so a
        // loopback/private target cannot slip through dressed as IPv6.
        if (b.length == 16 && isIpv4Mapped(b)) {
            try {
                return isInternal(InetAddress.getByAddress(Arrays.copyOfRange(b, 12, 16)));
            } catch (UnknownHostException e) {
                return true; // cannot normalize -> treat as internal (fail closed)
            }
        }
        if (a.isLoopbackAddress() || a.isAnyLocalAddress() || a.isLinkLocalAddress()
                || a.isSiteLocalAddress() || a.isMulticastAddress()) {
            return true; // 127/8, ::1, 0.0.0.0, 169.254/16 (incl. cloud metadata), 10/8 172.16/12 192.168/16, fe80::, etc.
        }
        if (b.length == 4) {
            int first = b[0] & 0xFF, second = b[1] & 0xFF;
            if (first == 0) {
                return true; // 0.0.0.0/8 "this network" (isAnyLocalAddress matches only 0.0.0.0 itself)
            }
            if (first == 100 && (second & 0xC0) == 0x40) {
                return true; // 100.64.0.0/10 carrier-grade NAT (RFC 6598), not flagged site-local by the JDK
            }
        }
        return b.length == 16 && (b[0] & 0xfe) == 0xfc; // IPv6 unique-local fc00::/7
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

    /** The configured allow-list of internal host names (system property or environment variable). */
    public static Set<String> configuredAllowlist() {
        String value = System.getProperty("lws.authn.allowedInternalHosts");
        if (value == null || value.isBlank()) {
            value = System.getenv("LWS_AUTHN_ALLOWED_INTERNAL_HOSTS");
        }
        if (value == null || value.isBlank()) {
            return Collections.emptySet();
        }
        Set<String> hosts = new LinkedHashSet<>();
        for (String h : value.split(",")) {
            String t = h.trim().toLowerCase(Locale.ROOT);
            if (!t.isEmpty()) {
                hosts.add(t);
            }
        }
        return hosts;
    }
}
