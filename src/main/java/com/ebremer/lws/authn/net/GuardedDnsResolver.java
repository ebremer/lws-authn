/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * The DNS resolver installed on the HTTP client the verifiers use. Making the SSRF check part of name
 * resolution is what closes the DNS-rebinding window: the addresses that are vetted are the very
 * addresses the connection manager then connects to.
 */
package com.ebremer.lws.authn.net;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.apache.http.conn.DnsResolver;

/**
 * An Apache HttpClient {@link DnsResolver} that resolves a host and vets every returned address with
 * {@link SsrfGuard#resolveAndVet(String)} before handing it to the connection manager.
 *
 * <p>Checking the URL and then letting the HTTP stack resolve the name again leaves a
 * time-of-check/time-of-use gap: a hostile name server can answer the check with a public address and
 * the connection with an internal one. Resolving <em>once</em>, inside the resolver the client
 * actually uses, removes the gap entirely — there is no second lookup to poison.</p>
 *
 * <p>It also means any host that was never vetted is unreachable through this client, which is a
 * second line of defence behind {@code disableRedirectHandling()}: even a followed redirect could only
 * reach an address this guard approved.</p>
 *
 * @author Erich Bremer
 */
final class GuardedDnsResolver implements DnsResolver {

    @Override
    public InetAddress[] resolve(String host) throws UnknownHostException {
        return SsrfGuard.resolveAndVet(host);
    }
}
