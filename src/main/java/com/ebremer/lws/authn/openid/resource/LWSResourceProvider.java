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
import java.util.Locale;

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

/**
 * @author Erich Bremer
 */
public class LWSResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public LWSResourceProvider(KeycloakSession session) {
        this.session = session;
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
                                                    @HeaderParam("Accept") String accept) {
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        String issuer = Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
        String webId = issuer + "/" + LWSConstants.RESOURCE_PROVIDER_ID + "/" + LWSConstants.CID_PATH + "/" + user.getId();

        ControlledIdentifierDocument cid = new ControlledIdentifierDocument(webId, issuer);

        String contentType = negotiate(accept);
        String body = switch (contentType) {
            case LWSConstants.TURTLE -> cid.toRdf(RDFFormat.TURTLE);
            case LWSConstants.N_TRIPLES -> cid.toRdf(RDFFormat.NTRIPLES);
            case LWSConstants.RDF_XML -> cid.toRdf(RDFFormat.RDFXML);
            default -> cid.toJsonLd();
        };
        return Response.ok(body, contentType).build();
    }

    /**
     * Verifies an ID Token as an LWS authentication credential, running the specification's
     * validation algorithm: dereference {@code sub} to a controlled identifier document, confirm it
     * lists {@code iss} as an OpenID Provider service, perform OpenID Connect Discovery and validate
     * the signature.
     *
     * <p>The credential may be supplied as the {@code credential} form parameter or as a
     * {@code Bearer} authorization header.</p>
     */
    @POST
    @Path(LWSConstants.VERIFY_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response verify(@FormParam("credential") String credential,
                           @HeaderParam("Authorization") String authorization) {
        String token = credential;
        if ((token == null || token.isBlank()) && authorization != null
                && authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            token = authorization.substring(7).trim();
        }
        if (token == null || token.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"missing 'credential' form parameter or Bearer token\"}")
                    .type(MediaType.APPLICATION_JSON).build();
        }

        VerificationResult result = new LWSCredentialVerifier(session).verify(token);
        try {
            return Response.ok(JsonSerialization.writeValueAsPrettyString(result), MediaType.APPLICATION_JSON)
                    .status(result.isValid() ? Response.Status.OK : Response.Status.UNAUTHORIZED)
                    .build();
        } catch (IOException e) {
            return Response.serverError().build();
        }
    }

    /** Minimal Accept negotiation: pick the first supported RDF syntax, defaulting to JSON-LD. */
    private static String negotiate(String accept) {
        if (accept == null || accept.isBlank()) {
            return LWSConstants.JSON_LD;
        }
        String a = accept.toLowerCase(Locale.ROOT);
        if (a.contains(LWSConstants.TURTLE)) {
            return LWSConstants.TURTLE;
        }
        if (a.contains(LWSConstants.N_TRIPLES)) {
            return LWSConstants.N_TRIPLES;
        }
        if (a.contains(LWSConstants.RDF_XML)) {
            return LWSConstants.RDF_XML;
        }
        return LWSConstants.JSON_LD; // application/ld+json, application/json, */* or unspecified
    }
}
