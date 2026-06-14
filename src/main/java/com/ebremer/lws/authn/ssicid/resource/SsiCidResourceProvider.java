/*
 * Copyright Erich Bremer.
 *
 * JAX-RS resource for the self-signed CID suite:
 *
 *   GET  {…}/lws-ssi-cid/cid/{userId}   the user's controlled identifier document, publishing the
 *                                       user's registered public JWK(s) as authentication methods
 *   POST {…}/lws-ssi-cid/verify         verify a self-issued JWT as an LWS authentication credential
 */
package com.ebremer.lws.authn.ssicid.resource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.fasterxml.jackson.databind.JsonNode;
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

import com.ebremer.lws.authn.ssicid.SsiCidConstants;
import com.ebremer.lws.authn.ssicid.cid.SelfSignedControlledIdentifierDocument;
import com.ebremer.lws.authn.ssicid.verify.SelfSignedCidVerifier;
import com.ebremer.lws.authn.ssicid.verify.SsiCidVerificationResult;

/**
 * @author Erich Bremer
 */
public class SsiCidResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public SsiCidResourceProvider(KeycloakSession session) {
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
     * Serves the user's controlled identifier document, publishing each public JWK held in the
     * {@code lws_jwk} user attribute as an {@code authentication} verification method.
     */
    @GET
    @Path(SsiCidConstants.CID_PATH + "/{userId}")
    @Produces({SsiCidConstants.JSON_LD, SsiCidConstants.TURTLE, SsiCidConstants.N_TRIPLES, SsiCidConstants.RDF_XML})
    public Response getControlledIdentifierDocument(@PathParam("userId") String userId,
                                                    @HeaderParam("Accept") String accept) {
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        String issuer = Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
        String webId = issuer + "/" + SsiCidConstants.RESOURCE_PROVIDER_ID + "/" + SsiCidConstants.CID_PATH + "/" + user.getId();

        List<JsonNode> jwks = new ArrayList<>();
        user.getAttributeStream(SsiCidConstants.JWK_ATTRIBUTE).forEach(value -> {
            try {
                JsonNode node = JsonSerialization.mapper.readTree(value);
                if (node.isObject()) {
                    jwks.add(node);
                }
            } catch (IOException ignore) {
                // skip attribute values that are not valid JWK JSON
            }
        });

        SelfSignedControlledIdentifierDocument cid = new SelfSignedControlledIdentifierDocument(webId, jwks);

        String contentType = negotiate(accept);
        String body = switch (contentType) {
            case SsiCidConstants.TURTLE -> cid.toRdf(RDFFormat.TURTLE);
            case SsiCidConstants.N_TRIPLES -> cid.toRdf(RDFFormat.NTRIPLES);
            case SsiCidConstants.RDF_XML -> cid.toRdf(RDFFormat.RDFXML);
            default -> cid.toJsonLd();
        };
        return Response.ok(body, contentType).build();
    }

    /**
     * Verifies a self-issued JWT as an LWS authentication credential. The credential may be supplied
     * as the {@code credential} form parameter or as a {@code Bearer} authorization header.
     */
    @POST
    @Path(SsiCidConstants.VERIFY_PATH)
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

        SsiCidVerificationResult result = new SelfSignedCidVerifier(session).verify(token);
        try {
            return Response.ok(JsonSerialization.writeValueAsPrettyString(result), MediaType.APPLICATION_JSON)
                    .status(result.isValid() ? Response.Status.OK : Response.Status.UNAUTHORIZED)
                    .build();
        } catch (IOException e) {
            return Response.serverError().build();
        }
    }

    private static String negotiate(String accept) {
        if (accept == null || accept.isBlank()) {
            return SsiCidConstants.JSON_LD;
        }
        String a = accept.toLowerCase(Locale.ROOT);
        if (a.contains(SsiCidConstants.TURTLE)) {
            return SsiCidConstants.TURTLE;
        }
        if (a.contains(SsiCidConstants.N_TRIPLES)) {
            return SsiCidConstants.N_TRIPLES;
        }
        if (a.contains(SsiCidConstants.RDF_XML)) {
            return SsiCidConstants.RDF_XML;
        }
        return SsiCidConstants.JSON_LD;
    }
}
