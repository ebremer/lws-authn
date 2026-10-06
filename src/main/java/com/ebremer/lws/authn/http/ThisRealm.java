/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * The realm a verify request arrived at, seen as a verifier sees any issuer and identity host.
 */
package com.ebremer.lws.authn.http;

import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;

import com.ebremer.lws.authn.net.OutboundHttp;
import com.ebremer.lws.authn.net.SsrfGuard;
import com.ebremer.lws.authn.rdf.RdfContentNegotiation;
import com.ebremer.lws.authn.rdf.RdfParsing;

/**
 * The realm serving this request: its issuer URL, its users and its keys.
 *
 * <p>A credential this realm issued, or about a subject whose document this realm hosts, used to be
 * verified by fetching from this realm over HTTP — three loopback requests for one of its own ID Tokens,
 * each holding a worker thread while it waited on another, and each needing this server's own address
 * on the SSRF allow-list (R-26). The verifiers ask this instead, when the URL is this realm's: the keys
 * its JWK set would list, and the document its {@code cid/{userId}} endpoint would serve, rendered by
 * the same code.</p>
 *
 * <p>"This realm's" is decided by the issuer URL Keycloak writes into the tokens it issues for this
 * request — {@link #issuerOf}, the frontend URL — so a URL naming this realm by some other host still
 * goes over HTTP, exactly as before.</p>
 *
 * @author Erich Bremer
 */
public final class ThisRealm {

    private final String issuer;
    private final Function<String, UserModel> users;
    private final Supplier<Stream<KeyWrapper>> keys;

    /**
     * @param issuer the realm's issuer URL
     * @param users  looks a user up by id; {@code null} when there is none
     * @param keys   the realm's keys
     */
    public ThisRealm(String issuer, Function<String, UserModel> users, Supplier<Stream<KeyWrapper>> keys) {
        this.issuer = issuer;
        this.users = users;
        this.keys = keys;
    }

    /** The realm of {@code session}'s request, or {@code null} when there is no realm to speak of. */
    public static ThisRealm of(KeycloakSession session) {
        if (session == null) {
            return null;
        }
        try {
            KeycloakContext context = session.getContext();
            RealmModel realm = context == null ? null : context.getRealm();
            if (realm == null) {
                return null;
            }
            return new ThisRealm(issuerOf(session, realm), id -> session.users().getUserById(realm, id),
                    () -> session.keys().getKeysStream(realm));
        } catch (RuntimeException unavailable) {
            return null;
        }
    }

    /** {@code realm}'s issuer URL for this request: the {@code iss} Keycloak writes into its tokens. */
    public static String issuerOf(KeycloakSession session, RealmModel realm) {
        return Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
    }

    public String issuer() {
        return issuer;
    }

    /** The realm's keys, as its JWK set would list them and more: filter for what you need. */
    public Stream<KeyWrapper> keys() {
        return keys.get();
    }

    /**
     * What this realm's {@code cid/{userId}} endpoint of {@code providerId} would answer a verifier for
     * {@code url}, rendered here; or {@code null} when {@code url} is not one of those documents, or not
     * in a form simple enough to be sure what the endpoint would do with it — then it is fetched.
     *
     * <p>The answer is the endpoint's: a {@code 404} for a user who does not exist, otherwise the document
     * in the syntax a verifier's {@code Accept} negotiates, describing the identifier the endpoint
     * derives from the user's id. The verifier then reads it exactly as it reads a fetched one.</p>
     */
    public OutboundHttp.Fetched document(String url, String providerId, String cidPath,
                                         CidEndpoint.DocumentRenderer renderer) {
        String prefix = issuer + "/" + providerId + "/" + cidPath + "/";
        if (url == null || !url.startsWith(prefix)) {
            return null;
        }
        // A plain-http identifier is refused when fetched (R-07); left to the fetch, it still is.
        java.net.URI parsed;
        try {
            parsed = new java.net.URI(url);
        } catch (java.net.URISyntaxException malformed) {
            return null;
        }
        if (!SsrfGuard.secureOrAllowListed(parsed.getScheme(), parsed.getHost(), SsrfGuard.configuredAllowlist())) {
            return null;
        }
        String userId = url.substring(prefix.length());
        if (userId.isEmpty() || userId.chars().anyMatch(c -> c == '/' || c == '?' || c == '#' || c == '%')) {
            return null;
        }
        UserModel user = users.apply(userId);
        if (user == null) {
            return new OutboundHttp.Fetched(404, "application/json", null);
        }
        String contentType = RdfContentNegotiation.best(RdfParsing.ACCEPT);
        String webId = CidEndpoint.documentUrl(issuer, providerId, cidPath, user.getId());
        return new OutboundHttp.Fetched(200, contentType, renderer.render(user, issuer, webId, contentType));
    }
}
