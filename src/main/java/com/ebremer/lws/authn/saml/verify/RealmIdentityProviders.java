/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * SAML trust taken from a realm's SAML identity providers.
 */
package com.ebremer.lws.authn.saml.verify;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.jboss.logging.Logger;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;

/**
 * Trusts, for an issuer, the signing certificates of the realm's enabled SAML identity providers whose
 * IdP entity ID is that issuer.
 *
 * <p>An administrator configuring a SAML identity provider in Keycloak has already established the
 * trust the suite means — out of band, by entity ID and signing certificate — and Keycloak keeps several
 * certificates per IdP for rotation. Matching on the entity ID binds each certificate to one issuer: a
 * relying party that instead tried every certificate it trusted accepted IdP A signing an assertion
 * that named IdP B as its issuer, with B's user as the subject (R-25).</p>
 *
 * <p>Only certificates configured on the identity provider are used. One that takes its keys from a
 * metadata descriptor URL at login, without a certificate configured, has none to offer here.</p>
 *
 * @author Erich Bremer
 */
public final class RealmIdentityProviders implements SamlTrust {

    private static final Logger log = Logger.getLogger(RealmIdentityProviders.class);

    private final Supplier<Stream<IdentityProviderModel>> identityProviders;

    /**
     * @param identityProviders the realm's identity providers, asked for once per verification
     *                          ({@code session.identityProviders()::getAllStream} inside Keycloak)
     */
    public RealmIdentityProviders(Supplier<Stream<IdentityProviderModel>> identityProviders) {
        this.identityProviders = identityProviders;
    }

    @Override
    public List<TrustedCertificate> certificatesFor(String issuer) {
        List<TrustedCertificate> trusted = new ArrayList<>();
        if (issuer == null || issuer.isBlank()) {
            return trusted;
        }
        try (Stream<IdentityProviderModel> all = identityProviders.get()) {
            all.filter(model -> SAMLIdentityProviderFactory.PROVIDER_ID.equals(model.getProviderId()))
                    .filter(IdentityProviderModel::isEnabled)
                    .map(SAMLIdentityProviderConfig::new)
                    .filter(config -> issuer.equals(config.getIdpEntityId()))
                    .forEach(config -> {
                        String[] certificates = config.getSigningCertificates();
                        for (String encoded : certificates == null ? new String[0] : certificates) {
                            X509Certificate certificate = decode(encoded, config.getAlias());
                            if (certificate != null) {
                                trusted.add(new TrustedCertificate(certificate, SOURCE_IDENTITY_PROVIDER,
                                        config.getAlias()));
                            }
                        }
                    });
        }
        return trusted;
    }

    /**
     * A configured signing certificate: base64 DER, as Keycloak stores it, or PEM. Read with the JDK
     * rather than Keycloak's {@code PemUtils}, which needs Keycloak's crypto provider initialised.
     */
    private static X509Certificate decode(String encoded, String alias) {
        if (encoded == null || encoded.isBlank()) {
            return null;
        }
        String base64 = encoded.replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "").replaceAll("\\s", "");
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(base64)));
        } catch (CertificateException | IllegalArgumentException | ClassCastException unreadable) {
            log.debugf("identity provider '%s': a signing certificate could not be read: %s", alias,
                    unreadable.getMessage());
            return null;
        }
    }
}
