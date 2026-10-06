/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Where the certificates a SAML credential may be checked against come from.
 */
package com.ebremer.lws.authn.saml.verify;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * The SAML suite's "trust relationship with the issuing identity provider", which it says must be
 * "established out-of-band": the certificates trusted to sign for an issuer.
 *
 * <p>Asked with the {@code <Issuer>} the assertion claims, before its signature is checked — the answer
 * decides which keys may check it, so a certificate trusted for one IdP cannot vouch for an assertion
 * naming another (R-25).</p>
 *
 * @author Erich Bremer
 */
@FunctionalInterface
public interface SamlTrust {

    /** {@link TrustedCertificate#source()} of a certificate the caller sent with the request. */
    String SOURCE_REQUEST = "request";

    /** {@link TrustedCertificate#source()} of a certificate from one of the realm's SAML identity providers. */
    String SOURCE_IDENTITY_PROVIDER = "identity-provider";

    /**
     * The certificates trusted to sign for {@code issuer}, in the order to try them.
     *
     * @param issuer the assertion's {@code <Issuer>}, not yet verified; may be {@code null}
     * @return empty when nothing is trusted to sign for it
     */
    List<TrustedCertificate> certificatesFor(String issuer);

    /**
     * A certificate and where it came from.
     *
     * @param certificate      the IdP signing certificate
     * @param source           {@link #SOURCE_REQUEST} or {@link #SOURCE_IDENTITY_PROVIDER}
     * @param identityProvider the alias of the identity provider it came from, or {@code null}
     */
    record TrustedCertificate(X509Certificate certificate, String source, String identityProvider) {
    }

    /**
     * Trust in one certificate the caller supplied, whatever issuer the assertion names: the caller has
     * made the trust decision, and the result can say no more than that this certificate signed it.
     */
    static SamlTrust certificate(X509Certificate certificate) {
        List<TrustedCertificate> only = List.of(new TrustedCertificate(certificate, SOURCE_REQUEST, null));
        return issuer -> only;
    }
}
