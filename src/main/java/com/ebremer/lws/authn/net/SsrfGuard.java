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
        return allowedHosts.contains(normalize(host).toLowerCase(Locale.ROOT));
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

    /** The configured allow-list of internal host names. */
    public static Set<String> configuredAllowlist() {
        return ServerSettings.allowedInternalHosts();
    }
}
