/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.net;

import org.apache.http.client.HttpClient;
import org.keycloak.broker.provider.util.SimpleHttp;

/**
 * Bridges {@link SimpleHttp} onto an HTTP client of our choosing.
 *
 * <p>Keycloak's {@code SimpleHttp} exposes only {@code doGet(url, session)} publicly, which binds the
 * request to the server-wide client — the one whose redirect behaviour is a deployment setting and
 * whose DNS resolution the verifier cannot vet. The constructor that takes an explicit client is
 * {@code protected}, so a subclass is the supported way to reach it.</p>
 *
 * @author Erich Bremer
 */
final class LwsSimpleHttp extends SimpleHttp {

    private LwsSimpleHttp(String url, HttpClient client, long maxConsumedResponseSize) {
        super(url, "GET", client, maxConsumedResponseSize);
    }

    /** A GET bound to {@code client} rather than to the session's shared client. */
    static SimpleHttp get(String url, HttpClient client, long maxConsumedResponseSize) {
        return new LwsSimpleHttp(url, client, maxConsumedResponseSize);
    }
}
