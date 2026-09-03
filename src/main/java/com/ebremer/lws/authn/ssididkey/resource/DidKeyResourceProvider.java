/*
 * Copyright Erich Bremer.
 *
 * JAX-RS resource for the self-signed did:key suite:
 *
 *   POST {…}/lws-ssi-did-key/verify   verify a self-issued did:key JWT as an LWS credential
 *
 * There is no controlled identifier document to serve — the public key is carried in the did:key
 * subject itself.
 */
package com.ebremer.lws.authn.ssididkey.resource;

import java.io.IOException;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.ssididkey.DidKeyConstants;
import com.ebremer.lws.authn.ssididkey.verify.DidKeyVerificationResult;
import com.ebremer.lws.authn.ssididkey.verify.SelfSignedDidKeyVerifier;
import com.ebremer.lws.authn.verify.VerifyAccess;

/**
 * @author Erich Bremer
 */
public class DidKeyResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final VerifyAccess access;

    public DidKeyResourceProvider(KeycloakSession session, VerifyAccess access) {
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
     * Verifies a self-issued did:key JWT. The credential is supplied as the {@code credential} form
     * parameter; the {@code Authorization} header carries the <em>caller's</em> own credential (see
     * {@link com.ebremer.lws.authn.verify.VerifyAccess}), and only falls back to meaning the
     * credential to verify in {@code public} access mode.
     *
     * <p>The optional {@code audience} parameter names the target authorization server, which the
     * suite requires the credential's {@code aud} to include.</p>
     */
    @POST
    @Path(DidKeyConstants.VERIFY_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response verify(@FormParam("credential") String credential,
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

        DidKeyVerificationResult result = new SelfSignedDidKeyVerifier().verify(token, expectedAudience);
        try {
            return Response.ok(JsonSerialization.writeValueAsPrettyString(result), MediaType.APPLICATION_JSON)
                    .status(result.isValid() ? Response.Status.OK : Response.Status.UNAUTHORIZED)
                    .build();
        } catch (IOException e) {
            return Response.serverError().build();
        }
    }
}
