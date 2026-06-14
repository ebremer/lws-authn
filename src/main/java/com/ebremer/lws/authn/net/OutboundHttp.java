/*
 * Copyright Erich Bremer.
 *
 * Outbound HTTP policy for verifier fetches driven by attacker-influenced URLs (the OpenID and
 * self-signed CID verifiers dereference the credential's `sub`/`iss` and fetch OIDC discovery / JWKS).
 * Every such fetch is bounded in time and in the number of bytes consumed, so a malicious or slow
 * target cannot stall the (unauthenticated) verify endpoint or exhaust memory. Pair with
 * {@link SsrfGuard}, which vets the URL's scheme and resolved address first.
 */
package com.ebremer.lws.authn.net;

import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;

/**
 * Builds {@link SimpleHttp} GETs pre-configured with bounded timeouts and a response-size cap.
 *
 * @author Erich Bremer
 */
public final class OutboundHttp {

    private OutboundHttp() {
    }

    /** Connect / read / connection-request timeout applied to each outbound fetch (milliseconds). */
    public static final int TIMEOUT_MS = 5_000;

    /**
     * Maximum response body the verifiers will consume. Controlled identifier documents, OIDC
     * discovery documents and JWK sets are all small (a few KB); 256&nbsp;KiB is a generous ceiling
     * that still rejects a hostile target streaming an unbounded body.
     */
    public static final long MAX_RESPONSE_BYTES = 256L * 1024L;

    /** A {@link SimpleHttp} GET with the bounded timeouts and response-size cap already applied. */
    public static SimpleHttp get(String url, KeycloakSession session) {
        return SimpleHttp.doGet(url, session)
                .connectTimeoutMillis(TIMEOUT_MS)
                .connectionRequestTimeoutMillis(TIMEOUT_MS)
                .socketTimeOutMillis(TIMEOUT_MS)
                .setMaxConsumedResponseSize(MAX_RESPONSE_BYTES);
    }
}
