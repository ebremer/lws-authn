/*
 * Copyright Erich Bremer.
 *
 * JAX-RS resource for the SAML 2.0 suite:
 *
 *   POST {…}/lws-saml/verify   verify a signed SAML 2.0 Response as an LWS authentication credential
 *
 * Because SAML trust is established out of band, the caller supplies the trusted IdP signing
 * certificate; there is no controlled identifier document to serve.
 */
package com.ebremer.lws.authn.saml.resource;

import java.io.IOException;
import java.security.cert.X509Certificate;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.common.util.PemUtils;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.saml.SamlConstants;
import com.ebremer.lws.authn.saml.verify.SamlCredentialVerifier;
import com.ebremer.lws.authn.saml.verify.SamlVerificationResult;

/**
 * @author Erich Bremer
 */
public class SamlResourceProvider implements RealmResourceProvider {

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
        // nothing to release
    }

    /**
     * Verifies a signed SAML 2.0 Response. Parameters:
     * <ul>
     *   <li>{@code credential} — the SAML Response (raw XML or base64-encoded XML)</li>
     *   <li>{@code certificate} — the trusted IdP signing certificate, PEM-encoded (required; SAML
     *       trust is out of band)</li>
     *   <li>{@code audience} — optional audience the assertion must be restricted to</li>
     * </ul>
     */
    @POST
    @Path(SamlConstants.VERIFY_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response verify(@FormParam("credential") String credential,
                           @FormParam("certificate") String certificatePem,
                           @FormParam("audience") String audience) {
        if (credential == null || credential.isBlank()) {
            return badRequest("missing 'credential' form parameter (the SAML Response)");
        }
        if (certificatePem == null || certificatePem.isBlank()) {
            return badRequest("missing 'certificate' form parameter "
                    + "(the trusted IdP signing certificate in PEM form; SAML trust is out-of-band)");
        }

        X509Certificate certificate;
        try {
            certificate = PemUtils.decodeCertificate(certificatePem);
        } catch (Exception e) {
            return badRequest("could not parse 'certificate' as a PEM X.509 certificate");
        }
        if (certificate == null) {
            return badRequest("could not parse 'certificate' as a PEM X.509 certificate");
        }

        SamlVerificationResult result = new SamlCredentialVerifier().verify(credential, certificate, audience);
        try {
            return Response.ok(JsonSerialization.writeValueAsPrettyString(result), MediaType.APPLICATION_JSON)
                    .status(result.isValid() ? Response.Status.OK : Response.Status.UNAUTHORIZED)
                    .build();
        } catch (IOException e) {
            return Response.serverError().build();
        }
    }

    private static Response badRequest(String message) {
        return Response.status(Response.Status.BAD_REQUEST)
                .entity("{\"error\":\"" + message + "\"}")
                .type(MediaType.APPLICATION_JSON).build();
    }
}
