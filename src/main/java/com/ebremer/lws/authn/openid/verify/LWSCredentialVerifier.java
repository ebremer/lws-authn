/*
 * Copyright Erich Bremer.
 *
 * Validates an ID Token as an LWS authentication credential, per
 * https://w3c.github.io/lws-protocol/lws10-authn-openid/#authentication-credential-validation
 *
 * Algorithm:
 *   1. The signing algorithm MUST NOT be "none".
 *   2. Dereference the 'sub' claim to a controlled identifier document (CID).
 *   3. The CID MUST list a service with type https://www.w3.org/ns/lws#OpenIdProvider whose
 *      serviceEndpoint equals the 'iss' claim.
 *   4. Perform OpenID Connect Discovery on 'iss' and locate the signing JWK.
 *   5. Validate the JWT signature and the active (exp/nbf) window.
 *
 * RDF parsing of the (possibly arbitrary-syntax) controlled identifier document uses Apache Jena.
 */
package com.ebremer.lws.authn.openid.verify;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.List;

import com.ebremer.lws.authn.net.OutboundHttp;
import com.ebremer.lws.authn.net.SsrfGuard;
import com.ebremer.lws.authn.rdf.RdfParsing;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.vocabulary.RDF;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.IDToken;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.openid.LWSConstants;

/**
 * @author Erich Bremer
 */
public class LWSCredentialVerifier {

    private final KeycloakSession session;

    public LWSCredentialVerifier(KeycloakSession session) {
        this.session = session;
    }

    public VerificationResult verify(String credential) {
        VerificationResult result = new VerificationResult();
        try {
            JWSInput jws = new JWSInput(credential);
            JWSHeader header = jws.getHeader();
            IDToken token = JsonSerialization.readValue(jws.getContent(), IDToken.class);

            String sub = token.getSubject();
            String iss = token.getIssuer();
            result.setSubject(sub);
            result.setIssuer(iss);

            // 1. The ID Token MUST NOT use "none" as the signing algorithm.
            String alg = header.getRawAlgorithm();
            boolean algOk = alg != null && !"none".equalsIgnoreCase(alg);
            result.check("signingAlgorithmNotNone", algOk);
            if (!algOk) {
                result.error("ID Token MUST NOT use 'none' as the signing algorithm");
                return result.fail();
            }
            if (isBlank(sub)) {
                result.check("subjectPresent", false);
                result.error("ID Token is missing the 'sub' claim");
                return result.fail();
            }
            if (isBlank(iss)) {
                result.check("issuerPresent", false);
                result.error("ID Token is missing the 'iss' claim");
                return result.fail();
            }

            // 2. Trust establishment: dereference the subject to a controlled identifier document.
            Model cid = dereference(sub, result);
            if (cid == null) {
                return result.fail();
            }

            // 3. The CID must declare iss as an OpenID Provider service for the subject.
            boolean serviceOk = declaresOpenIdProvider(cid, sub, iss);
            result.check("openIdProviderServiceLocated", serviceOk);
            if (!serviceOk) {
                result.error("Controlled identifier document for <" + sub + "> does not declare a "
                        + LWSConstants.OPENID_PROVIDER_TYPE + " service with serviceEndpoint <" + iss + ">");
                return result.fail();
            }

            // 4. OpenID Connect Discovery -> signing key.
            PublicKey publicKey = resolveSigningKey(iss, header, result);
            if (publicKey == null) {
                return result.fail();
            }

            // 4b. Pin the token's declared algorithm to the discovered key type. Without this a forged
            // token could claim a symmetric alg (e.g. HS256) and have the OP's RSA public key treated
            // as the HMAC secret — the classic algorithm-confusion attack.
            boolean algMatchesKey = algMatchesKey(alg, publicKey);
            result.check("algorithmMatchesKey", algMatchesKey);
            if (!algMatchesKey) {
                result.error("ID Token 'alg' " + alg + " is not consistent with the discovered "
                        + publicKey.getAlgorithm() + " signing key");
                return result.fail();
            }

            // 5. Signature verification.
            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, alg);
            if (signatureProvider == null) {
                result.check("signatureValid", false);
                result.error("No signature provider available for algorithm " + alg);
                return result.fail();
            }
            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setKid(header.getKeyId());
            keyWrapper.setAlgorithm(alg);
            keyWrapper.setType(publicKey.getAlgorithm());
            keyWrapper.setUse(KeyUse.SIG);
            keyWrapper.setPublicKey(publicKey);

            SignatureVerifierContext verifierContext = signatureProvider.verifier(keyWrapper);
            boolean signatureValid = verifierContext.verify(
                    jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8), jws.getSignature());
            result.check("signatureValid", signatureValid);
            if (!signatureValid) {
                result.error("ID Token signature is invalid");
                return result.fail();
            }

            // The credential MUST carry an expiry and be within its exp/nbf window. Keycloak's
            // isActive() treats a missing 'exp' as "never expires", so require it explicitly: a
            // captured ID Token must not be replayable indefinitely.
            Long exp = token.getExp();
            boolean notExpired = exp != null && exp != 0 && token.isActive();
            result.check("notExpired", notExpired);
            if (!notExpired) {
                result.error(exp == null || exp == 0
                        ? "ID Token is missing the required 'exp' claim"
                        : "ID Token is expired or not yet valid");
                return result.fail();
            }

            // The ID Token's 'aud' (the OIDC client) is intentionally not validated here: the LWS OpenID
            // suite establishes identity via sub + iss + the CID's OpenIdProvider service. Audience
            // confinement is applied by the relying party via Resource Indicators (RFC 8707) / Token
            // Exchange (RFC 8693). See the README "Audience / token exchange" note.
            result.setValid(result.getErrors().isEmpty());
        } catch (Exception e) {
            result.error(e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage()));
            return result.fail();
        }
        return result;
    }

    /**
     * Dereferences the subject URL and parses the returned controlled identifier document into a Jena
     * model. Turtle is preferred (the WebID/Solid norm and the syntax this extension serves);
     * N-Triples and RDF/XML are parsed with Jena RIOT; JSON-LD is interpreted directly (see
     * {@link #modelFromCompactJsonLd}).
     */
    private Model dereference(String sub, VerificationResult result) {
        try {
            SsrfGuard.verify(sub); // refuse to dereference internal/loopback targets (SSRF)
            SimpleHttp.Response response = OutboundHttp.get(sub, session)
                    .header("Accept", LWSConstants.TURTLE + ", " + LWSConstants.JSON_LD + ";q=0.9, "
                            + LWSConstants.N_TRIPLES + ";q=0.8, " + LWSConstants.RDF_XML + ";q=0.7")
                    .asResponse();
            if (response.getStatus() != 200) {
                result.check("subjectDereferenced", false);
                result.error("Dereferencing 'sub' <" + sub + "> returned HTTP " + response.getStatus());
                return null;
            }
            String contentType = response.getFirstHeader("Content-Type");
            String body = response.asString();
            Model model = RdfParsing.isJsonLd(contentType, body)
                    ? modelFromCompactJsonLd(body, sub)
                    : RdfParsing.parseRdf(body, contentType, sub);
            result.check("subjectDereferenced", true);
            return model;
        } catch (Exception e) {
            result.check("subjectDereferenced", false);
            result.error("Failed to dereference/parse 'sub' <" + sub + ">: " + e.getMessage());
            return null;
        }
    }

    /**
     * Builds a Jena model from a compact JSON-LD controlled identifier document, without invoking a
     * full JSON-LD processor (which would couple this provider to a specific Titanium version that
     * conflicts with the one Keycloak ships). Handles the standardized CID shape used by this and
     * other LWS implementations: a subject {@code id} with one or more {@code service} entries each
     * carrying {@code type} and {@code serviceEndpoint}. Exotic JSON-LD framings that remap these
     * terms are not expanded.
     */
    private Model modelFromCompactJsonLd(String body, String sub) throws IOException {
        JsonNode doc = JsonSerialization.mapper.readTree(body);
        Model model = ModelFactory.createDefaultModel();
        Property service = model.createProperty(LWSConstants.DID_SERVICE);
        Property serviceEndpoint = model.createProperty(LWSConstants.DID_SERVICE_ENDPOINT);

        String id = firstNonBlank(text(doc, "id"), text(doc, "@id"), sub);
        Resource subject = model.createResource(id);

        JsonNode services = doc.get("service");
        if (services != null) {
            for (JsonNode svc : services.isArray() ? services : List.of(services)) {
                Resource node = model.createResource();
                String type = firstNonBlank(text(svc, "type"), text(svc, "@type"), null);
                if (type != null) {
                    node.addProperty(RDF.type, model.createResource(type));
                }
                String endpoint = endpointValue(svc.get("serviceEndpoint"));
                if (endpoint != null) {
                    node.addProperty(serviceEndpoint, model.createResource(endpoint));
                }
                subject.addProperty(service, node);
            }
        }
        return model;
    }

    private static String endpointValue(JsonNode endpoint) {
        if (endpoint == null) {
            return null;
        }
        if (endpoint.isTextual()) {
            return endpoint.asText();
        }
        if (endpoint.isObject() && endpoint.hasNonNull("@id")) {
            return endpoint.get("@id").asText();
        }
        if (endpoint.isArray() && !endpoint.isEmpty()) {
            return endpointValue(endpoint.get(0));
        }
        return null;
    }

    private static String firstNonBlank(String a, String b, String fallback) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        if (b != null && !b.isBlank()) {
            return b;
        }
        return fallback;
    }

    /**
     * ASKs whether the CID declares iss as an LWS OpenID Provider service for the subject. The
     * attacker-controlled {@code sub} and {@code iss} are bound as IRI parameters (never concatenated)
     * so they cannot break out of the {@code <...>} and inject SPARQL.
     */
    private static boolean declaresOpenIdProvider(Model cid, String sub, String iss) {
        ParameterizedSparqlString pss = new ParameterizedSparqlString();
        pss.setNsPrefix("did", LWSConstants.DID_NS);
        pss.setCommandText("ASK { ?sub did:service ?svc . ?svc a ?providerType ; did:serviceEndpoint ?iss . }");
        pss.setIri("sub", sub);
        pss.setIri("providerType", LWSConstants.OPENID_PROVIDER_TYPE);
        pss.setIri("iss", iss);
        try (QueryExecution qe = QueryExecutionFactory.create(pss.asQuery(), cid)) {
            return qe.execAsk();
        }
    }

    /** Performs OpenID Connect Discovery on iss and returns the public key matching the token's kid. */
    private PublicKey resolveSigningKey(String iss, JWSHeader header, VerificationResult result) {
        try {
            String base = iss.endsWith("/") ? iss.substring(0, iss.length() - 1) : iss;
            String discoveryUrl = base + "/.well-known/openid-configuration";
            SsrfGuard.verify(discoveryUrl);
            SimpleHttp.Response discovery = OutboundHttp.get(discoveryUrl, session).asResponse();
            if (discovery.getStatus() != 200) {
                result.check("jwksResolved", false);
                result.error("OpenID discovery for <" + iss + "> returned HTTP " + discovery.getStatus());
                return null;
            }
            JsonNode config = discovery.asJson();
            String discoveredIssuer = text(config, "issuer");
            boolean issuerOk = iss.equals(discoveredIssuer);
            result.check("issuerDiscoveryMatches", issuerOk);
            if (!issuerOk) {
                result.error("OpenID discovery issuer mismatch: expected <" + iss + ">, got <" + discoveredIssuer + ">");
                return null;
            }
            String jwksUri = text(config, "jwks_uri");
            if (jwksUri == null) {
                result.check("jwksResolved", false);
                result.error("OpenID configuration has no jwks_uri");
                return null;
            }
            SsrfGuard.verify(jwksUri);
            JSONWebKeySet keySet = OutboundHttp.get(jwksUri, session).asJson(JSONWebKeySet.class);
            String kid = header.getKeyId();
            String alg = header.getRawAlgorithm();
            if (keySet.getKeys() != null) {
                for (JWK jwk : keySet.getKeys()) {
                    if (kid != null && !kid.equals(jwk.getKeyId())) {
                        continue;
                    }
                    PublicKey pk = JWKParser.create(jwk).toPublicKey();
                    if (!algMatchesKey(alg, pk)) {
                        continue; // ignore keys whose type cannot produce this token's alg
                    }
                    result.check("jwksResolved", true);
                    return pk;
                }
            }
            result.check("jwksResolved", false);
            result.error("No JWK matched the token (kid=" + kid + ", alg=" + alg + ")");
            return null;
        } catch (Exception e) {
            result.check("jwksResolved", false);
            result.error("OpenID Connect discovery failed for <" + iss + ">: " + e.getMessage());
            return null;
        }
    }

    /**
     * True iff the JOSE {@code alg} is an asymmetric signature algorithm whose key type matches
     * {@code key}. Pinning the token's declared algorithm to the discovered signing key blocks
     * algorithm-confusion: symmetric ({@code HS*}), {@code none} and unknown algorithms never match,
     * so an RSA/EC public key can never be misused as an HMAC secret.
     */
    private static boolean algMatchesKey(String alg, PublicKey key) {
        if (alg == null || key == null) {
            return false;
        }
        String keyType = key.getAlgorithm();
        if (alg.startsWith("RS") || alg.startsWith("PS")) {   // RSASSA-PKCS1-v1_5 / RSASSA-PSS
            return "RSA".equals(keyType);
        }
        if (alg.startsWith("ES")) {                           // ECDSA
            return "EC".equals(keyType) || "ECDSA".equals(keyType);
        }
        if ("EdDSA".equals(alg) || alg.startsWith("Ed")) {    // Edwards-curve EdDSA
            return "EdDSA".equals(keyType) || "Ed25519".equals(keyType) || "Ed448".equals(keyType);
        }
        return false;
    }

    private static String text(JsonNode node, String field) {
        return node != null && node.hasNonNull(field) ? node.get(field).asText() : null;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
