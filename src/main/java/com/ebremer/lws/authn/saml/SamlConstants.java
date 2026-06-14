/*
 * Copyright Erich Bremer.
 *
 * Constants for the LWS 1.0 SAML 2.0 Authentication Suite.
 * Specification: https://w3c.github.io/lws-protocol/lws10-authn-saml/
 */
package com.ebremer.lws.authn.saml;

/**
 * Constants for the SAML 2.0 authentication suite.
 *
 * <p>Unlike the OpenID and self-signed suites, this suite establishes trust in the identity provider
 * <em>out of band</em>: there is no controlled identifier document to dereference and no service
 * discovery. The credential is a signed SAML 2.0 {@code <Response>}; a verifier validates the XML
 * signature against a <em>pre-configured</em> IdP certificate and reads the subject from
 * {@code <NameID>}.</p>
 *
 * @author Erich Bremer
 */
public final class SamlConstants {

    private SamlConstants() {
    }

    /** OAuth token-type URI for SAML 2.0 assertions used as credentials in this suite. */
    public static final String TOKEN_TYPE_SAML2 = "urn:ietf:params:oauth:token-type:saml2";

    /** SAML 2.0 assertion namespace. */
    public static final String SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

    /** SAML 2.0 protocol namespace. */
    public static final String SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";

    /** Persistent NameID format (used by the specification's example for the controlled identifier). */
    public static final String NAMEID_FORMAT_PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";

    /**
     * {@code RealmResourceProviderFactory} id. Endpoints are mounted at
     * {@code {frontendUrl}/realms/{realm}/lws-saml}.
     */
    public static final String RESOURCE_PROVIDER_ID = "lws-saml";

    /** Sub-path of the credential verification utility: {@code …/lws-saml/verify}. */
    public static final String VERIFY_PATH = "verify";
}
