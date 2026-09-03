/*
 * Copyright Erich Bremer.
 *
 * JAX-RS resource exposing the LWS endpoints:
 *
 *   GET  {issuer}/lws/cid/{userId}   the user's controlled identifier document (content negotiated)
 *   POST {issuer}/lws/verify         verify an ID Token as an LWS authentication credential
 */
package com.ebremer.lws.authn.openid.resource;

import java.io.IOException;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.apache.jena.riot.RDFFormat;
import com.ebremer.lws.authn.rdf.RdfContentNegotiation;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.Urls;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.openid.LWSConstants;
import com.ebremer.lws.authn.openid.cid.ControlledIdentifierDocument;
import com.ebremer.lws.authn.openid.verify.LWSCredentialVerifier;
import com.ebremer.lws.authn.openid.verify.VerificationResult;
import com.ebremer.lws.authn.verify.VerifyAccess;

/**
 * @author Erich Bremer
 */
public class LWSResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final VerifyAccess access;

    public LWSResourceProvider(KeycloakSession session, VerifyAccess access) {
        this.session = session;
        this.access = access;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
        // nothing to release
    }

    /**
     * Serves the controlled identifier document for a user. This is the document a verifier
     * dereferences from the {@code sub} claim; it declares this realm's issuer as the user's
     * {@code https://www.w3.org/ns/lws#OpenIdProvider} service.
     *
     * <p>Content negotiated: JSON-LD (default), Turtle, N-Triples, RDF/XML.</p>
     */
    @GET
    @Path(LWSConstants.CID_PATH + "/{userId}")
    @Produces({LWSConstants.JSON_LD, LWSConstants.TURTLE, LWSConstants.N_TRIPLES, LWSConstants.RDF_XML})
    public Response getControlledIdentifierDocument(@PathParam("userId") String userId,
                                                    @HeaderParam("Accept") String accept,
                                                    @HeaderParam("If-None-Match") String ifNoneMatch) {
        // Negotiated before anything is looked up: if we cannot serve a syntax the client accepts,
        // there is nothing useful to do with the user record.
        String contentType = RdfContentNegotiation.best(accept);
        if (contentType == null) {
            return notAcceptable();
        }
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            // Typed for the same reason as the 406 above: Keycloak rejects a response with no content
            // type and returns 500 instead.
            return Response.status(Response.Status.NOT_FOUND)
                    .entity("{\"error\":\"not_found\"}")
                    .type(MediaType.APPLICATION_JSON)
                    .build();
        }

        String issuer = Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
        String webId = issuer + "/" + LWSConstants.RESOURCE_PROVIDER_ID + "/" + LWSConstants.CID_PATH + "/" + user.getId();

        ControlledIdentifierDocument cid = new ControlledIdentifierDocument(webId, issuer);

        String body = switch (contentType) {
            case LWSConstants.TURTLE -> cid.toRdf(RDFFormat.TURTLE);
            case LWSConstants.N_TRIPLES -> cid.toRdf(RDFFormat.NTRIPLES);
            case LWSConstants.RDF_XML -> cid.toRdf(RDFFormat.RDFXML);
            default -> cid.toJsonLd();
        };
        return serve(contentType, body, ifNoneMatch);
    }

    /**
     * Verifies an ID Token as an LWS authentication credential, running the specification's
     * validation algorithm: dereference {@code sub} to a controlled identifier document, confirm it
     * lists {@code iss} as an OpenID Provider service, perform OpenID Connect Discovery and validate
     * the signature.
     *
     * <p>The credential is supplied as the {@code credential} form parameter. The
     * {@code Authorization} header carries the <em>caller's</em> own credential (see
     * {@link com.ebremer.lws.authn.verify.VerifyAccess}); only in {@code public} access mode does it
     * fall back to meaning the credential to verify.</p>
     *
     * <p>Two optional parameters turn on the audience half of OpenID Connect Core 3.1.3.7, which the
     * suite incorporates by reference:</p>
     * <ul>
     *   <li>{@code client_id} — the relying party's own identifier. When given, {@code aud} must list
     *       it and {@code azp} must equal it (steps 3-5).</li>
     *   <li>{@code audience} — an additional audience the credential must be restricted to, typically
     *       the authorization server.</li>
     * </ul>
     */
    @POST
    @Path(LWSConstants.VERIFY_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response verify(@FormParam("credential") String credential,
                           @FormParam("client_id") String expectedClientId,
                           @FormParam("audience") String expectedAudience,
                           @HeaderParam("Authorization") String authorization) {
        Response denied = access.check(session, authorization);
        if (denied != null) {
            return denied;
        }
        String token = credential;
        if ((token == null || token.isBlank()) && access.allowsCredentialInAuthorizationHeader()) {
            token = VerifyAccess.bearerToken(authorization);
        }
        if (token == null || token.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"missing 'credential' form parameter or Bearer token\"}")
                    .type(MediaType.APPLICATION_JSON).build();
        }

        VerificationResult result =
                new LWSCredentialVerifier(session).verify(token, expectedClientId, expectedAudience);
        try {
            return Response.ok(JsonSerialization.writeValueAsPrettyString(result), MediaType.APPLICATION_JSON)
                    .status(result.isValid() ? Response.Status.OK : Response.Status.UNAUTHORIZED)
                    .build();
        } catch (IOException e) {
            return Response.serverError().build();
        }
    }

    /**
     * Serves a negotiated representation with the cache headers a controlled identifier document
     * should carry. {@code Vary: Accept} because the body depends on it; an {@code ETag} and
     * {@code Cache-Control} because both suite drafts encourage verifiers to cache these documents "to
     * reduce unnecessary network requests and the associated metadata leakage", which they can only do
     * if the server says how.
     */
    private static Response serve(String contentType, String body, String ifNoneMatch) {
        String entityTag = RdfContentNegotiation.entityTag(body);
        Response.ResponseBuilder response = RdfContentNegotiation.matches(ifNoneMatch, entityTag)
                ? Response.notModified(entityTag)
                : Response.ok(body, contentType).tag(entityTag);
        return response
                .header("Vary", "Accept")
                .header("Cache-Control", "public, max-age=" + RdfContentNegotiation.CACHE_SECONDS)
                .build();
    }

    /**
     * 406 naming the syntaxes on offer, rather than silently serving one that was not asked for.
     *
     * <p>Carries a body deliberately: Keycloak's {@code DefaultSecurityHeadersProvider} logs
     * "MediaType not set" and turns any response without a content type into a 500, so an empty 406
     * never reaches the client as a 406.</p>
     */
    private static Response notAcceptable() {
        return Response.status(Response.Status.NOT_ACCEPTABLE)
                .entity("{\"error\":\"not_acceptable\",\"supported\":[\""
                        + String.join("\",\"", RdfContentNegotiation.SUPPORTED) + "\"]}")
                .type(MediaType.APPLICATION_JSON)
                .header("Vary", "Accept")
                .build();
    }
}
