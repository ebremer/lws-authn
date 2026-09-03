/*
 * Copyright Erich Bremer.
 *
 * JAX-RS resource exposing the LWS endpoints:
 *
 *   GET  {issuer}/lws/cid/{userId}   the user's controlled identifier document (content negotiated)
 *   POST {issuer}/lws/verify         verify an ID Token as an LWS authentication credential
 */
package com.ebremer.lws.authn.openid.resource;

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
import org.keycloak.services.resource.RealmResourceProvider;

import com.ebremer.lws.authn.config.EndpointSettings;
import com.ebremer.lws.authn.http.CidEndpoint;
import com.ebremer.lws.authn.http.JsonResponses;
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
    private final EndpointSettings settings;

    public LWSResourceProvider(KeycloakSession session, EndpointSettings settings) {
        this.session = session;
        this.settings = settings;
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
     * <p>Content negotiated: JSON-LD (default), Turtle, N-Triples, RDF/XML. See {@link CidEndpoint}
     * for why it is unauthenticated and what bounds that.</p>
     */
    @GET
    @Path(LWSConstants.CID_PATH + "/{userId}")
    @Produces({LWSConstants.JSON_LD, LWSConstants.TURTLE, LWSConstants.N_TRIPLES, LWSConstants.RDF_XML})
    public Response getControlledIdentifierDocument(@PathParam("userId") String userId,
                                                    @HeaderParam("Accept") String accept,
                                                    @HeaderParam("If-None-Match") String ifNoneMatch) {
        return CidEndpoint.serve(session, settings, LWSConstants.CID_PATH, userId, accept, ifNoneMatch,
                (user, issuer, webId, contentType) -> {
                    ControlledIdentifierDocument cid = new ControlledIdentifierDocument(webId, issuer);
                    return switch (contentType) {
                        case LWSConstants.TURTLE -> cid.toRdf(RDFFormat.TURTLE);
                        case LWSConstants.N_TRIPLES -> cid.toRdf(RDFFormat.NTRIPLES);
                        case LWSConstants.RDF_XML -> cid.toRdf(RDFFormat.RDFXML);
                        default -> cid.toJsonLd();
                    };
                });
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
     *       the authorization server. A deployment can require one for every request with the
     *       {@code audience} setting, so a caller that forgets the parameter does not silently accept
     *       a credential minted for somewhere else.</li>
     * </ul>
     *
     * <p><strong>An invalid credential is a {@code 200}</strong> carrying {@code "valid": false}, not a
     * {@code 401}: the request was authorized and this is its answer. A {@code 401} from this endpoint
     * means the <em>caller</em> was refused, and carries a {@code WWW-Authenticate} challenge.</p>
     */
    @POST
    @Path(LWSConstants.VERIFY_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response verify(@FormParam("credential") String credential,
                           @FormParam("client_id") String expectedClientId,
                           @FormParam("audience") String expectedAudience,
                           @HeaderParam("Authorization") String authorization) {
        if (!settings.isEnabled(session.getContext().getRealm())) {
            return JsonResponses.notEnabled();
        }
        VerifyAccess access = settings.getVerifyAccess();
        Response denied = access.check(session, authorization);
        if (denied != null) {
            return denied;
        }
        String token = credential;
        if ((token == null || token.isBlank()) && access.allowsCredentialInAuthorizationHeader()) {
            token = VerifyAccess.bearerToken(authorization);
        }
        if (token == null || token.isBlank()) {
            return JsonResponses.badRequest("missing 'credential' form parameter or Bearer token");
        }

        VerificationResult result = new LWSCredentialVerifier(session)
                .verify(token, expectedClientId, settings.audienceFor(expectedAudience));
        return JsonResponses.of(Response.Status.OK, result);
    }
}
