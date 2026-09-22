/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * JAX-RS resource for the self-signed did:key suite:
 *
 *   POST {…}/lws-ssi-did-key/verify   verify a self-issued did:key JWT as an LWS credential
 *
 * DEPRECATED. The LWS Working Group discontinued this suite on 18 September 2026 in favour of the
 * self-signed CID suite, whose verifier (POST {…}/lws-ssi-cid/verify) now resolves did:key subjects.
 * This endpoint keeps its old behaviour for existing callers and says so on every response:
 *
 *   Deprecation: @1789689600                                   (RFC 9745)
 *   Link: <../lws-ssi-cid/verify>; rel="successor-version",
 *         <https://w3c.github.io/lws-protocol/lws10-authn-ssi-did-key/>; rel="deprecation"
 *
 * There is no controlled identifier document to serve — the public key is carried in the did:key
 * subject itself.
 */
package com.ebremer.lws.authn.ssididkey.resource;

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

import com.ebremer.lws.authn.config.EndpointSettings;
import com.ebremer.lws.authn.http.JsonResponses;
import com.ebremer.lws.authn.ssididkey.DidKeyConstants;
import com.ebremer.lws.authn.ssididkey.verify.DidKeyVerificationResult;
import com.ebremer.lws.authn.ssididkey.verify.SelfSignedDidKeyVerifier;
import com.ebremer.lws.authn.verify.VerifyAccess;

/**
 * @author Erich Bremer
 */
public class DidKeyResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final EndpointSettings settings;

    public DidKeyResourceProvider(KeycloakSession session, EndpointSettings settings) {
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
     * Verifies a self-issued did:key JWT. The credential is supplied as the {@code credential} form
     * parameter; the {@code Authorization} header carries the <em>caller's</em> own credential (see
     * {@link com.ebremer.lws.authn.verify.VerifyAccess}), and only falls back to meaning the
     * credential to verify in {@code public} access mode.
     *
     * <p>The optional {@code audience} parameter names the target authorization server, which the
     * suite requires the credential's {@code aud} to include; a deployment can supply one for every
     * request with the {@code audience} setting.</p>
     *
     * <p><strong>An invalid credential is a {@code 200}</strong> carrying {@code "valid": false}, not a
     * {@code 401}: the request was authorized and this is its answer. A {@code 401} from this endpoint
     * means the <em>caller</em> was refused, and carries a {@code WWW-Authenticate} challenge.</p>
     */
    @POST
    @Path(DidKeyConstants.VERIFY_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response verify(@FormParam("credential") String credential,
                           @FormParam("audience") String expectedAudience,
                           @HeaderParam("Authorization") String authorization) {
        return deprecated(answer(credential, expectedAudience, authorization));
    }

    private Response answer(String credential, String expectedAudience, String authorization) {
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

        DidKeyVerificationResult result =
                new SelfSignedDidKeyVerifier().verify(token, settings.audienceFor(expectedAudience));
        return JsonResponses.of(Response.Status.OK, result);
    }

    /**
     * Marks a response from this endpoint as deprecated (RFC 9745) and names its successor, on every
     * status — a caller learning the endpoint is going away from a {@code 401} is as useful as from a
     * {@code 200}. No {@code Sunset}: when to remove the endpoint is the operator's decision, and
     * {@code enabled=false} on this provider does it today.
     */
    static Response deprecated(Response response) {
        return Response.fromResponse(response)
                .header("Deprecation", DidKeyConstants.DEPRECATION)
                .header("Link", "<" + DidKeyConstants.SUCCESSOR_RELATIVE + ">; rel=\"successor-version\"")
                .header("Link", "<" + DidKeyConstants.SPECIFICATION + ">; rel=\"deprecation\"")
                .build();
    }
}
