/*
 * Copyright Erich Bremer.
 *
 * Constants for the LWS 1.0 OpenID Connect Authentication Suite.
 * Specification: https://w3c.github.io/lws-protocol/lws10-authn-openid/
 */
package com.ebremer.lws.authn.openid;

/**
 * Shared vocabulary, media types and routing constants used across the LWS Keycloak provider.
 *
 * @author Erich Bremer
 */
public final class LWSConstants {

    private LWSConstants() {
    }

    /** LWS vocabulary namespace. */
    public static final String LWS_NS = "https://www.w3.org/ns/lws#";

    /**
     * Service {@code type} that, in a controlled identifier document, marks the OpenID Provider
     * that issues LWS authentication credentials for the subject.
     */
    public static final String OPENID_PROVIDER_TYPE = LWS_NS + "OpenIdProvider";

    /** DID namespace. The CID v1 context maps {@code service}/{@code serviceEndpoint} into it. */
    public static final String DID_NS = "https://www.w3.org/ns/did#";

    /** Property linking a controlled identifier to a service description. */
    public static final String DID_SERVICE = DID_NS + "service";

    /** Property carrying the service endpoint (here, the OpenID Provider issuer URL). */
    public static final String DID_SERVICE_ENDPOINT = DID_NS + "serviceEndpoint";

    /** JSON-LD context for W3C Controlled Identifier Documents (CID 1.0). */
    public static final String CID_CONTEXT = "https://www.w3.org/ns/cid/v1";

    /** OAuth token-type URI to use for ID Tokens acting as LWS credentials (RFC 8693 exchanges). */
    public static final String TOKEN_TYPE_ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";

    /**
     * {@code RealmResourceProviderFactory} id. Endpoints are mounted at
     * {@code {issuer}/lws} i.e. {@code {frontendUrl}/realms/{realm}/lws}.
     */
    public static final String RESOURCE_PROVIDER_ID = "lws";

    /** Sub-path serving controlled identifier documents: {@code {issuer}/lws/cid/{userId}}. */
    public static final String CID_PATH = "cid";

    /** Sub-path of the credential verification utility: {@code {issuer}/lws/verify}. */
    public static final String VERIFY_PATH = "verify";

    // RDF media types
    public static final String JSON_LD = "application/ld+json";
    public static final String TURTLE = "text/turtle";
    public static final String N_TRIPLES = "application/n-triples";
    public static final String RDF_XML = "application/rdf+xml";
}
