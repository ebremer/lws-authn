/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * JAX-RS resource for the SAML 2.0 suite:
 *
 *   POST {…}/lws-saml/verify   verify a signed SAML 2.0 Response as an LWS authentication credential
 *
 * SAML trust is established out of band: by the realm's SAML identity providers, each an entity ID with
 * its signing certificates, or — unless the deployment turns it off — by a certificate the caller
 * supplies. There is no controlled identifier document to serve.
 */
package com.ebremer.lws.authn.saml.resource;

import java.security.cert.X509Certificate;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.common.util.PemUtils;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import com.ebremer.lws.authn.config.EndpointSettings;
import com.ebremer.lws.authn.http.JsonResponses;
import com.ebremer.lws.authn.saml.SamlConstants;
import com.ebremer.lws.authn.saml.verify.RealmIdentityProviders;
import com.ebremer.lws.authn.saml.verify.SamlCredentialVerifier;
import com.ebremer.lws.authn.saml.verify.SamlTrust;
import com.ebremer.lws.authn.saml.verify.SamlVerificationResult;
import com.ebremer.lws.authn.verify.VerifyAccess;

/**
 * @author Erich Bremer
 */
public class SamlResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final EndpointSettings settings;

    public SamlResourceProvider(KeycloakSession session, EndpointSettings settings) {
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
     * Verifies a signed SAML 2.0 Response. Parameters:
     * <ul>
     *   <li>{@code credential} — the SAML Response (raw XML or base64-encoded XML)</li>
     *   <li>{@code certificate} — optional: the trusted IdP signing certificate, PEM-encoded. Without
     *       it, the certificates of the realm's enabled SAML identity providers whose IdP entity ID is
     *       the assertion's {@code <Issuer>} are trusted (R-25). With the {@code request-certificates}
     *       setting off, sending one is a {@code 400}.</li>
     *   <li>{@code audience} — optional audience every {@code <AudienceRestriction>} must name; a
     *       deployment can supply one for every request with the {@code audience} setting</li>
     *   <li>{@code issuer} — optional {@code <Issuer>} the assertion must name: what binds a supplied
     *       certificate to an IdP</li>
     *   <li>{@code recipient} — optional bearer {@code Recipient}, the LWS client identifier, the
     *       assertion must name</li>
     *   <li>{@code allowExpiredCertificate} — {@code true} to accept an IdP certificate that is
     *       outside its own validity period. Off by default; only for offline analysis of an old
     *       credential, never for a live authentication decision.</li>
     * </ul>
     *
     * <p><strong>An invalid credential is a {@code 200}</strong> carrying {@code "valid": false}, not a
     * {@code 401}: the request was authorized and this is its answer. A {@code 401} from this endpoint
     * means the <em>caller</em> was refused, and carries a {@code WWW-Authenticate} challenge. A
     * {@code 400} means the request could not be read at all — a missing or unparseable parameter —
     * which is not a statement about any credential.</p>
     */
    @POST
    @Path(SamlConstants.VERIFY_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response verify(@FormParam("credential") String credential,
                           @FormParam("certificate") String certificatePem,
                           @FormParam("audience") String audience,
                           @FormParam("issuer") String issuer,
                           @FormParam("recipient") String recipient,
                           @FormParam("allowExpiredCertificate") String allowExpiredCertificate,
                           @HeaderParam("Authorization") String authorization) {
        if (!settings.isEnabled(session.getContext().getRealm())) {
            return JsonResponses.notEnabled();
        }
        Response denied = settings.getVerifyAccess().check(session, authorization);
        if (denied != null) {
            return denied;
        }
        if (credential == null || credential.isBlank()) {
            return JsonResponses.badRequest("missing 'credential' form parameter (the SAML Response)");
        }
        Response oversized = VerifyAccess.refuseOversized(credential);
        if (oversized != null) {
            return oversized;
        }
        SamlTrust trust;
        if (certificatePem == null || certificatePem.isBlank()) {
            trust = new RealmIdentityProviders(() -> session.identityProviders().getAllStream());
        } else if (!settings.acceptsRequestCertificates()) {
            return JsonResponses.badRequest("this server does not accept a 'certificate' parameter: SAML trust "
                    + "comes from the realm's SAML identity providers, so send the credential without one");
        } else {
            X509Certificate certificate;
            try {
                certificate = PemUtils.decodeCertificate(certificatePem);
            } catch (Exception e) {
                certificate = null;
            }
            if (certificate == null) {
                return JsonResponses.badRequest("could not parse 'certificate' as a PEM X.509 certificate");
            }
            trust = SamlTrust.certificate(certificate);
        }

        SamlVerificationResult result = new SamlCredentialVerifier().verify(credential, trust,
                settings.audienceFor(audience), issuer, recipient, Boolean.parseBoolean(allowExpiredCertificate));
        return JsonResponses.of(Response.Status.OK, result);
    }
}
