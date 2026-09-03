/*
 * Copyright Erich Bremer.
 *
 * Validates an ID Token as an LWS authentication credential, per
 * https://w3c.github.io/lws-protocol/lws10-authn-openid/#authentication-credential-validation
 *
 * Algorithm:
 *   1. The signing algorithm MUST NOT be "none", and no critical header may be present (RFC 7515).
 *   2. The credential MUST carry sub, iss and azp (the LWS subject, issuer and client identifiers).
 *   3. Dereference the 'sub' claim to a controlled identifier document (CID) whose 'id' equals 'sub'.
 *   4. The CID MUST list a service with type https://www.w3.org/ns/lws#OpenIdProvider whose
 *      serviceEndpoint equals the 'iss' claim.
 *   5. Perform OpenID Connect Discovery on 'iss' and locate the signing JWK.
 *   6. Validate the JWT signature and the active (exp/nbf) window.
 *   7. Apply OpenID Connect Core 3.1.3.7 steps 3-5 (aud/azp) against the expected client and
 *      audience, when the caller supplies them.
 *
 * RDF parsing of the (possibly arbitrary-syntax) controlled identifier document uses Apache Jena.
 */
package com.ebremer.lws.authn.openid.verify;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.List;

import com.ebremer.lws.authn.jose.JwsChecks;
import com.ebremer.lws.authn.net.OutboundHttp;
import com.ebremer.lws.authn.rdf.RdfParsing;
import com.ebremer.lws.authn.verify.Trace;
import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
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

    private static final Logger log = Logger.getLogger(LWSCredentialVerifier.class);

    private final KeycloakSession session;

    public LWSCredentialVerifier(KeycloakSession session) {
        this.session = session;
    }

    public VerificationResult verify(String credential) {
        return verify(credential, null, null);
    }

    /**
     * @param credential       the ID Token
     * @param expectedClientId the relying party's own client identifier. When supplied, OpenID Connect
     *                         Core 3.1.3.7 steps 3-5 are enforced: {@code aud} must contain it and
     *                         {@code azp} must equal it. The LWS suite says the JWT "MUST be validated
     *                         as described by OpenID Connect Core Section 3.1.3.7", and those steps are
     *                         what stops a token minted for one relying party being replayed at another.
     * @param expectedAudience an additional audience the credential must be restricted to, typically the
     *                         authorization server this verifier speaks for
     */
    public VerificationResult verify(String credential, String expectedClientId, String expectedAudience) {
        VerificationResult result = new VerificationResult();
        result.setTraceId(Trace.newId());
        result.setTokenType(LWSConstants.TOKEN_TYPE_ID_TOKEN);
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

            // RFC 7515 5.2: a JWS carrying critical header parameters the verifier does not implement
            // must be rejected. This provider implements none, so any 'crit' at all is fatal.
            List<String> critical = JwsChecks.criticalHeaders(jws);
            result.check("noUnsupportedCriticalHeaders", critical.isEmpty());
            if (!critical.isEmpty()) {
                result.error("ID Token carries unsupported critical header parameters: " + critical);
                return result.fail();
            }

            boolean typeOk = JwsChecks.typeIsJwtOrAbsent(header.getType());
            result.check("typeIsJwt", typeOk);
            if (!typeOk) {
                result.error("ID Token 'typ' header is not a JWT type");
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

            // The suite: "The ID Token MUST use the `azp` (authorized party) claim for the LWS client
            // identifier", and LWS core 4.1 makes the client a REQUIRED claim of every credential.
            String azp = token.getIssuedFor();
            result.setClient(azp);
            boolean clientPresent = !isBlank(azp);
            result.check("clientPresent", clientPresent);
            if (!clientPresent) {
                result.error("ID Token is missing the 'azp' claim (the LWS client identifier)");
                return result.fail();
            }

            // 2. Trust establishment: dereference the subject to a controlled identifier document.
            //    The suite requires "a valid controlled identifier document with an `id` value equal to
            //    the subject identifier", so the document must actually claim to be about this subject.
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
            boolean algMatchesKey = JwsChecks.algMatchesKey(alg, publicKey);
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
            keyWrapper.setType(JwsChecks.keycloakKeyType(publicKey));
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
            boolean notExpired = JwsChecks.withinValidityWindow(token);
            result.check("notExpired", notExpired);
            if (!notExpired) {
                result.error(exp == null || exp == 0
                        ? "ID Token is missing the required 'exp' claim"
                        : "ID Token is expired or not yet valid");
                return result.fail();
            }

            // OpenID Connect Core 3.1.3.7 steps 3-5. Without an expected client identifier there is
            // nothing to compare against, so these are enforced only when the caller says who it is —
            // but step 4 (multiple audiences require azp) holds unconditionally, and azp is already
            // required above, so the multi-audience case is covered either way.
            String[] audience = token.getAudience();
            if (!isBlank(expectedClientId)) {
                boolean audienceHasClient = JwsChecks.audienceIncludes(audience, expectedClientId);
                result.check("audienceContainsClient", audienceHasClient);
                if (!audienceHasClient) {
                    result.error("ID Token 'aud' does not list the expected client <" + expectedClientId + ">");
                    return result.fail();
                }
                boolean azpMatches = expectedClientId.equals(azp);
                result.check("authorizedPartyMatchesClient", azpMatches);
                if (!azpMatches) {
                    result.error("ID Token 'azp' is not the expected client <" + expectedClientId + ">");
                    return result.fail();
                }
            }
            if (!isBlank(expectedAudience)) {
                boolean audienceMatched = JwsChecks.audienceIncludes(audience, expectedAudience);
                result.check("audienceMatched", audienceMatched);
                if (!audienceMatched) {
                    result.error("ID Token 'aud' does not include <" + expectedAudience + ">");
                    return result.fail();
                }
            }

            result.setValid(result.getErrors().isEmpty());
        } catch (Exception e) {
            // Never echo the exception to the caller: it can name internal hosts, ports and library
            // internals. The detail goes to the log under the result's trace id.
            log.debugf(e, "[%s] LWS OpenID credential verification failed", result.getTraceId());
            result.error("Credential could not be validated");
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
            // OutboundHttp applies the SSRF policy, refuses a host that has been failing, and fetches
            // through a client that follows no redirects and resolves only vetted addresses.
            SimpleHttp.Response response = OutboundHttp.get(sub, session)
                    .header("Accept", LWSConstants.TURTLE + ", " + LWSConstants.JSON_LD + ";q=0.9, "
                            + LWSConstants.N_TRIPLES + ";q=0.8, " + LWSConstants.RDF_XML + ";q=0.7")
                    .asResponse();
            if (response.getStatus() != 200) {
                log.debugf("[%s] dereferencing sub <%s> returned HTTP %d", result.getTraceId(), sub,
                        response.getStatus());
                OutboundHttp.recordFailure(sub);
                result.check("subjectDereferenced", false);
                result.error("Dereferencing 'sub' <" + sub + "> did not return a controlled identifier document");
                return null;
            }
            String contentType = response.getFirstHeader("Content-Type");
            String body = response.asString();
            // JSON-LD is processed properly (Jena + Titanium, contexts served from this JAR) so a
            // conforming document verifies whatever shape it is written in. The compact reader stays
            // as a fallback for a document whose context this provider does not bundle, which is the
            // only interpretation it can offer without having read the term definitions.
            Model model = RdfParsing.parse(body, contentType, sub);
            if (model == null) {
                log.debugf("[%s] sub <%s> is JSON-LD this provider cannot process; reading the compact shape",
                        result.getTraceId(), sub);
                model = modelFromCompactJsonLd(body, sub);
            }
            OutboundHttp.recordSuccess(sub);
            result.check("subjectDereferenced", true);

            // CID 1.0: "A controlled identifier document MUST contain an `id` value in the topmost
            // map", and the suite requires that id to equal the subject. On the JSON-LD path
            // modelFromCompactJsonLd has already refused a document with no id or a different one; on
            // the RDF path the base IRI is the subject, so this asserts the graph really describes it
            // rather than some unrelated resource that merely happens to be served from that URL.
            boolean describesSubject = model.contains(model.createResource(sub), null, (org.apache.jena.rdf.model.RDFNode) null);
            result.check("subjectIdMatches", describesSubject);
            if (!describesSubject) {
                result.error("The document at 'sub' <" + sub + "> is not a controlled identifier document for it");
                return null;
            }
            return model;
        } catch (RdfParsing.UnsupportedSyntaxException wrongSyntax) {
            // Distinguished from the generic failure below because it is actionable and gives nothing
            // away: the media type is one the remote server chose to advertise publicly, and naming it
            // is the difference between "your document is not RDF" and "something went wrong".
            log.debugf("[%s] sub <%s> was served as '%s', which is not an RDF syntax this verifier reads",
                    result.getTraceId(), sub, wrongSyntax.getContentType());
            OutboundHttp.recordFailure(sub);
            result.check("subjectDereferenced", false);
            result.error("The document at 'sub' <" + sub + "> was served as '" + wrongSyntax.getContentType()
                    + "', which is not an RDF syntax this verifier reads");
            return null;
        } catch (Exception e) {
            // The cause can name the address the host resolved to, so it is logged, not returned.
            log.debugf(e, "[%s] could not dereference or parse sub <%s>", result.getTraceId(), sub);
            OutboundHttp.recordFailure(sub);
            result.check("subjectDereferenced", false);
            result.error("Failed to dereference 'sub' <" + sub + "> as a controlled identifier document");
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
     *
     * <p>The document's {@code id} must be present and equal to {@code sub}. Defaulting a missing
     * {@code id} to the subject, as this once did, would accept a document that never claimed to
     * describe that subject at all — which is exactly what the suite's "with an `id` value equal to
     * the subject identifier" exists to prevent.</p>
     */
    private Model modelFromCompactJsonLd(String body, String sub) throws IOException {
        JsonNode doc = JsonSerialization.mapper.readTree(body);
        Model model = ModelFactory.createDefaultModel();
        Property service = model.createProperty(LWSConstants.DID_SERVICE);
        Property serviceEndpoint = model.createProperty(LWSConstants.DID_SERVICE_ENDPOINT);

        String id = firstNonBlank(text(doc, "id"), text(doc, "@id"), null);
        if (id == null) {
            throw new IOException("controlled identifier document has no 'id'");
        }
        if (!id.equals(sub)) {
            throw new IOException("controlled identifier document 'id' does not equal the subject");
        }
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
        String discoveryUrl = null;
        try {
            String base = iss.endsWith("/") ? iss.substring(0, iss.length() - 1) : iss;
            discoveryUrl = base + "/.well-known/openid-configuration";
            SimpleHttp.Response discovery = OutboundHttp.get(discoveryUrl, session).asResponse();
            if (discovery.getStatus() != 200) {
                log.debugf("[%s] OpenID discovery for <%s> returned HTTP %d", result.getTraceId(), iss,
                        discovery.getStatus());
                OutboundHttp.recordFailure(discoveryUrl);
                result.check("jwksResolved", false);
                result.error("OpenID Connect Discovery for <" + iss + "> did not return a configuration document");
                return null;
            }
            JsonNode config = discovery.asJson();
            String discoveredIssuer = text(config, "issuer");
            boolean issuerOk = iss.equals(discoveredIssuer);
            result.check("issuerDiscoveryMatches", issuerOk);
            if (!issuerOk) {
                // The discovered issuer is a third party's response; log it rather than reflecting it.
                log.debugf("[%s] discovery issuer mismatch: expected <%s>, got <%s>", result.getTraceId(), iss,
                        discoveredIssuer);
                result.error("The OpenID configuration served for <" + iss + "> declares a different issuer");
                return null;
            }
            String jwksUri = text(config, "jwks_uri");
            if (jwksUri == null) {
                result.check("jwksResolved", false);
                result.error("The OpenID configuration for <" + iss + "> has no jwks_uri");
                return null;
            }
            JSONWebKeySet keySet = OutboundHttp.get(jwksUri, session).asJson(JSONWebKeySet.class);
            OutboundHttp.recordSuccess(discoveryUrl);
            String kid = header.getKeyId();
            String alg = header.getRawAlgorithm();
            if (keySet.getKeys() != null) {
                for (JWK jwk : keySet.getKeys()) {
                    if (kid != null && !kid.equals(jwk.getKeyId())) {
                        continue;
                    }
                    PublicKey pk = JWKParser.create(jwk).toPublicKey();
                    if (!JwsChecks.algMatchesKey(alg, pk)) {
                        continue; // ignore keys whose type cannot produce this token's alg
                    }
                    result.check("jwksResolved", true);
                    return pk;
                }
            }
            result.check("jwksResolved", false);
            result.error("No JWK published by <" + iss + "> matched the token (kid=" + kid + ", alg=" + alg + ")");
            return null;
        } catch (Exception e) {
            log.debugf(e, "[%s] OpenID Connect discovery failed for <%s>", result.getTraceId(), iss);
            if (discoveryUrl != null) {
                OutboundHttp.recordFailure(discoveryUrl);
            }
            result.check("jwksResolved", false);
            result.error("OpenID Connect Discovery failed for <" + iss + ">");
            return null;
        }
    }

    private static String text(JsonNode node, String field) {
        return node != null && node.hasNonNull(field) ? node.get(field).asText() : null;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
