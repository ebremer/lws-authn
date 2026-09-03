/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * The shared behaviour of the two `cid/{userId}` endpoints: content negotiation, rate limiting,
 * a uniform response shape and the cache headers a dereferenceable identity document should carry.
 */
package com.ebremer.lws.authn.http;

import jakarta.ws.rs.core.Response;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;

import com.ebremer.lws.authn.config.EndpointSettings;
import com.ebremer.lws.authn.rdf.RdfContentNegotiation;
import com.ebremer.lws.authn.verify.RateLimiter;
import com.ebremer.lws.authn.verify.VerifyAccess;

/**
 * Serves a controlled identifier document.
 *
 * <p>Both suites that host identifiers — OpenID and self-signed CID — expose the same endpoint over
 * the same lifecycle: negotiate, look the user up, build the document, serve it with validators. Only
 * the document differs, so only the document is a parameter.</p>
 *
 * <h2>These endpoints are deliberately unauthenticated</h2>
 *
 * <p>A controlled identifier is a URL other people dereference: that is what makes it an identifier
 * rather than a local user record. A verifier meets the subject for the first time <em>at</em> this
 * URL, before any trust exists in either direction, so there is no credential it could present. An
 * authenticated identity document would not be dereferenceable, and a suite built on dereferenceable
 * identifiers would not work.</p>
 *
 * <p>What that costs is enumeration: anyone may ask about any {@code {userId}}, and a 404 for an
 * unknown one confirms which ids exist. Two things bound it, since it cannot be closed:</p>
 * <ul>
 *   <li><strong>A uniform response shape.</strong> Every answer — the document, a 404, a 406, a 429 —
 *       is the same media type with the same body shape ({@link JsonResponses}), so nothing but the
 *       status distinguishes them and there is no incidental oracle in the wording, headers or
 *       structure of a refusal. The identifiers themselves are Keycloak user ids: random UUIDs, not
 *       guessable and not meaningful, so what enumeration yields is a list of opaque ids that were
 *       already published wherever the users authenticated.</li>
 *   <li><strong>A rate limit</strong> (default 600/minute per caller, an order of magnitude above the
 *       verify endpoints' — this is a cheap local read, and the ceiling exists to make scraping slow,
 *       not to ration legitimate verifiers). Configure it with {@code cid-rate-limit}; {@code 0} turns
 *       it off.</li>
 * </ul>
 *
 * @author Erich Bremer
 */
public final class CidEndpoint {

    private CidEndpoint() {
    }

    /** Builds the body of one user's controlled identifier document in a negotiated syntax. */
    @FunctionalInterface
    public interface DocumentRenderer {
        /**
         * @param user        the subject
         * @param issuer      this realm's issuer URL, which some documents cite as a service
         * @param webId       the identifier the document describes, as this endpoint derives it
         * @param contentType one of {@link RdfContentNegotiation#SUPPORTED}
         */
        String render(UserModel user, String issuer, String webId, String contentType);
    }

    /**
     * Runs the whole endpoint: negotiation, rate limit, lookup, rendering, cache headers.
     *
     * @param cidPath the sub-path this provider mounts the documents under (its {@code cid})
     */
    public static Response serve(KeycloakSession session, EndpointSettings settings, String cidPath,
                                 String userId, String accept, String ifNoneMatch,
                                 DocumentRenderer renderer) {
        RealmModel realm = session.getContext().getRealm();
        if (!settings.isEnabled(realm)) {
            return JsonResponses.notEnabled();
        }
        // Negotiated before anything is looked up: if we cannot serve a syntax the client accepts,
        // there is nothing useful to do with the user record.
        String contentType = RdfContentNegotiation.best(accept);
        if (contentType == null) {
            return JsonResponses.notAcceptable(RdfContentNegotiation.SUPPORTED);
        }
        RateLimiter limiter = settings.getCidLimiter();
        if (limiter != null && !limiter.tryAcquire(VerifyAccess.callerKey(session))) {
            return JsonResponses.error(Response.Status.TOO_MANY_REQUESTS, "slow_down",
                    "too many requests for identity documents; retry shortly");
        }
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return JsonResponses.notFound("no controlled identifier document for that identifier");
        }

        String issuer = Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
        String webId = issuer + "/" + settings.getProviderId() + "/" + cidPath + "/" + user.getId();

        String body = renderer.render(user, issuer, webId, contentType);
        return withValidators(contentType, body, ifNoneMatch, settings.getCidCacheSeconds());
    }

    /**
     * Serves a negotiated representation with the cache headers a controlled identifier document
     * should carry. {@code Vary: Accept} because the body depends on it; an {@code ETag} and
     * {@code Cache-Control} because both suite drafts encourage verifiers to cache these documents "to
     * reduce unnecessary network requests and the associated metadata leakage", which they can only do
     * if the server says how.
     */
    private static Response withValidators(String contentType, String body, String ifNoneMatch,
                                           long cacheSeconds) {
        String entityTag = RdfContentNegotiation.entityTag(body);
        Response.ResponseBuilder response = RdfContentNegotiation.matches(ifNoneMatch, entityTag)
                ? Response.notModified(entityTag)
                : Response.ok(body, contentType).tag(entityTag);
        return response
                .header("Vary", "Accept")
                .header("Cache-Control", "public, max-age=" + cacheSeconds)
                .build();
    }


}
