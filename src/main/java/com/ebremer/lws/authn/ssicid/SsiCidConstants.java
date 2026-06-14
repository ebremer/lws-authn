/*
 * Copyright Erich Bremer.
 *
 * Constants for the LWS 1.0 Self-signed Identity (Controlled Identifiers) Authentication Suite.
 * Specification: https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/
 */
package com.ebremer.lws.authn.ssicid;

/**
 * Vocabulary, media types and routing constants for the self-signed CID authentication suite.
 *
 * <p>In this suite there is no OpenID Provider: an agent signs its own JSON Web Token whose
 * {@code sub == iss == client_id} is a controlled identifier, and a verifier dereferences that
 * identifier to a controlled identifier document, selects the {@code authentication} verification
 * method whose key matches the JWT {@code kid}, and validates the signature against its
 * {@code publicKeyJwk}.</p>
 *
 * @author Erich Bremer
 */
public final class SsiCidConstants {

    private SsiCidConstants() {
    }

    /** Security vocabulary used by the CID v1 context for verification methods. */
    public static final String SEC_NS = "https://w3id.org/security#";

    /** {@code authentication} relationship (verification methods usable to authenticate). */
    public static final String SEC_AUTHENTICATION = SEC_NS + "authenticationMethod";

    /** Generic {@code verificationMethod} relationship (accepted as a fallback when verifying). */
    public static final String SEC_VERIFICATION_METHOD = SEC_NS + "verificationMethod";

    /** {@code controller} of a verification method. */
    public static final String SEC_CONTROLLER = SEC_NS + "controller";

    /** {@code publicKeyJwk} — a JSON literal carrying the public JWK. */
    public static final String SEC_PUBLIC_KEY_JWK = SEC_NS + "publicKeyJwk";

    /** {@code JsonWebKey} verification-method type. */
    public static final String JSON_WEB_KEY_TYPE = SEC_NS + "JsonWebKey";

    /** JSON-LD context for W3C Controlled Identifier Documents (CID 1.0). */
    public static final String CID_CONTEXT = "https://www.w3.org/ns/cid/v1";

    /** {@code rdf:JSON} datatype IRI ({@code publicKeyJwk} is a JSON literal). */
    public static final String RDF_JSON = "http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON";

    /** OAuth token-type URI for self-issued JWTs used as credentials in this suite. */
    public static final String TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt";

    /**
     * {@code RealmResourceProviderFactory} id. Endpoints are mounted at
     * {@code {frontendUrl}/realms/{realm}/lws-ssi-cid}.
     */
    public static final String RESOURCE_PROVIDER_ID = "lws-ssi-cid";

    /** Sub-path serving controlled identifier documents: {@code …/lws-ssi-cid/cid/{userId}}. */
    public static final String CID_PATH = "cid";

    /** Sub-path of the credential verification utility: {@code …/lws-ssi-cid/verify}. */
    public static final String VERIFY_PATH = "verify";

    /**
     * User attribute holding the agent's public JWK(s). Each value is a JWK JSON object (with a
     * {@code kid}); multiple values are published as multiple {@code authentication} methods.
     */
    public static final String JWK_ATTRIBUTE = "lws_jwk";

    // RDF media types
    public static final String JSON_LD = "application/ld+json";
    public static final String TURTLE = "text/turtle";
    public static final String N_TRIPLES = "application/n-triples";
    public static final String RDF_XML = "application/rdf+xml";
}
