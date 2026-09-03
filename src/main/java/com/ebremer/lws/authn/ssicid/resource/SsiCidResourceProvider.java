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
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.config.EndpointSettings;
import com.ebremer.lws.authn.http.CidEndpoint;
import com.ebremer.lws.authn.http.JsonResponses;
import com.ebremer.lws.authn.jose.PublicJwk;
import com.ebremer.lws.authn.ssicid.SsiCidConstants;
import com.ebremer.lws.authn.ssicid.cid.SelfSignedControlledIdentifierDocument;
import com.ebremer.lws.authn.ssicid.verify.SelfSignedCidVerifier;
import com.ebremer.lws.authn.ssicid.verify.SsiCidVerificationResult;
import com.ebremer.lws.authn.verify.VerifyAccess;

/**
 * @author Erich Bremer
 */
public class SsiCidResourceProvider implements RealmResourceProvider {

    private static final Logger log = Logger.getLogger(SsiCidResourceProvider.class);

    private final KeycloakSession session;
    private final EndpointSettings settings;

    public SsiCidResourceProvider(KeycloakSession session, EndpointSettings settings) {
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
     * Serves the user's controlled identifier document, publishing each public JWK held in the
     * {@code lws_jwk} user attribute as an {@code authentication} verification method.
     *
     * <p>See {@link CidEndpoint} for why this endpoint is unauthenticated and what bounds that.</p>
     */
    @GET
    @Path(SsiCidConstants.CID_PATH + "/{userId}")
    @Produces({SsiCidConstants.JSON_LD, SsiCidConstants.TURTLE, SsiCidConstants.N_TRIPLES, SsiCidConstants.RDF_XML})
    public Response getControlledIdentifierDocument(@PathParam("userId") String userId,
                                                    @HeaderParam("Accept") String accept,
                                                    @HeaderParam("If-None-Match") String ifNoneMatch) {
        return CidEndpoint.serve(session, settings, SsiCidConstants.CID_PATH, userId, accept, ifNoneMatch,
                (user, issuer, webId, contentType) -> {
                    SelfSignedControlledIdentifierDocument cid =
                            new SelfSignedControlledIdentifierDocument(webId, publishableJwks(user));
                    return switch (contentType) {
                        case SsiCidConstants.TURTLE -> cid.toRdf(RDFFormat.TURTLE);
                        case SsiCidConstants.N_TRIPLES -> cid.toRdf(RDFFormat.NTRIPLES);
                        case SsiCidConstants.RDF_XML -> cid.toRdf(RDFFormat.RDFXML);
                        default -> cid.toJsonLd();
                    };
                });
    }

    /**
     * The user's registered JWKs, filtered to the ones that may be published.
     *
     * <p>Only the public half of a key may ever appear here (CID 1.0: a publicKeyJwk map "MUST NOT
     * include any members of the private information class, such as `d`"). The attribute is
     * operator-managed free text, so one mis-pasted key pair would otherwise publish an agent's
     * private key at this world-readable URL. A JWK carrying private material is dropped outright,
     * with a warning, rather than trimmed: the key is already compromised and quietly serving its
     * public half would hide that from the operator.</p>
     */
    private static List<JsonNode> publishableJwks(UserModel user) {
        List<JsonNode> jwks = new ArrayList<>();
        user.getAttributeStream(SsiCidConstants.JWK_ATTRIBUTE).forEach(value -> {
            JsonNode node;
            try {
                node = JsonSerialization.mapper.readTree(value);
            } catch (IOException notJson) {
                log.warnf("Ignoring a '%s' value on user %s: it is not valid JSON",
                        SsiCidConstants.JWK_ATTRIBUTE, user.getId());
                return;
            }
            PublicJwk.sanitize(node).ifPresentOrElse(jwks::add, () ->
                    log.warnf("Refusing to publish a '%s' value on user %s: %s",
                            SsiCidConstants.JWK_ATTRIBUTE, user.getId(), PublicJwk.describeRejection(node)));
        });
        return jwks;
    }

    /**
     * Verifies a self-issued JWT as an LWS authentication credential. The credential is supplied as
     * the {@code credential} form parameter; the {@code Authorization} header carries the
     * <em>caller's</em> own credential (see {@link com.ebremer.lws.authn.verify.VerifyAccess}), and
     * only falls back to meaning the credential to verify in {@code public} access mode.
     *
     * <p>The optional {@code audience} parameter names the target authorization server, which the
     * suite requires the credential's {@code aud} to include. Without it only the presence of an
     * audience restriction can be checked, so a deployment can supply one for every request with the
     * {@code audience} setting.</p>
     *
     * <p><strong>An invalid credential is a {@code 200}</strong> carrying {@code "valid": false}, not a
     * {@code 401}: the request was authorized and this is its answer. A {@code 401} from this endpoint
     * means the <em>caller</em> was refused, and carries a {@code WWW-Authenticate} challenge.</p>
     */
    @POST
    @Path(SsiCidConstants.VERIFY_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response verify(@FormParam("credential") String credential,
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

        SsiCidVerificationResult result =
                new SelfSignedCidVerifier(session).verify(token, settings.audienceFor(expectedAudience));
        return JsonResponses.of(Response.Status.OK, result);
    }
}
