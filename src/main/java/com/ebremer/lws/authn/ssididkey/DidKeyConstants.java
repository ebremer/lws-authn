/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Constants for the LWS 1.0 Self-signed Identity (did:key) Authentication Suite.
 * Specification: https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/ — DISCONTINUED on
 * 18 September 2026 in favour of the self-signed CID suite, which now resolves did:key subjects itself.
 */
package com.ebremer.lws.authn.ssididkey;

/**
 * Constants for the self-signed {@code did:key} authentication suite.
 *
 * <p>This is the most self-contained suite: the subject is a {@code did:key} identifier that
 * <em>embeds</em> the public key (multibase base58btc + multicodec). An agent self-signs a JWT
 * ({@code sub == iss == client_id ==} that {@code did:key}); a verifier decodes the key directly from
 * the identifier — there is no document to dereference and no key hosting.</p>
 *
 * @author Erich Bremer
 */
public final class DidKeyConstants {

    private DidKeyConstants() {
    }

    /** OAuth token-type URI for self-issued JWTs used as credentials in this suite. */
    public static final String TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt";

    /** Scheme prefix of a {@code did:key} identifier. */
    public static final String DID_KEY_PREFIX = "did:key:";

    /**
     * {@code RealmResourceProviderFactory} id. The verify endpoint is mounted at
     * {@code {frontendUrl}/realms/{realm}/lws-ssi-did-key}.
     */
    public static final String RESOURCE_PROVIDER_ID = "lws-ssi-did-key";

    /** Sub-path of the credential verification utility: {@code …/lws-ssi-did-key/verify}. */
    public static final String VERIFY_PATH = "verify";

    /** The editor's draft, which now carries the discontinuation notice. */
    public static final String SPECIFICATION = "https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/";

    /**
     * When the LWS Working Group discontinued this suite: 2026-09-18T00:00:00Z, as an RFC 9745
     * {@code Deprecation} header value (a Structured Field Date: {@code @} and Unix seconds).
     */
    public static final String DEPRECATION = "@1789689600";

    /**
     * The successor endpoint, relative to this one ({@code …/lws-ssi-did-key/verify}), for the
     * {@code Link: <…>; rel="successor-version"} header: the self-signed CID suite's verifier, which
     * accepts did:key subjects.
     */
    public static final String SUCCESSOR_RELATIVE = "../lws-ssi-cid/verify";
}
