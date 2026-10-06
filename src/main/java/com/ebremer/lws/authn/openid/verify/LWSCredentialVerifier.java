/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
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
 *   7. Apply OpenID Connect Core §3.1.3.7's audience rules (aud must contain the client; azp must be
 *      it) against the expected client and audience, when the caller supplies them.
 *
 * RDF parsing of the (possibly arbitrary-syntax) controlled identifier document uses Apache Jena.
 */
package com.ebremer.lws.authn.openid.verify;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;

import com.ebremer.lws.authn.config.ServerSettings;
import com.ebremer.lws.authn.http.CidEndpoint;
import com.ebremer.lws.authn.http.ThisRealm;
import com.ebremer.lws.authn.jose.JwsChecks;
import com.ebremer.lws.authn.net.OutboundHttp;
import com.ebremer.lws.authn.net.SsrfGuard;
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
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.IDToken;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.TokenUtil;

import com.ebremer.lws.authn.openid.LWSConstants;

/**
 * @author Erich Bremer
 */
public class LWSCredentialVerifier {

    private static final Logger log = Logger.getLogger(LWSCredentialVerifier.class);

    private final KeycloakSession session;
    private ThisRealm thisRealm;
    private CidEndpoint.DocumentRenderer ownDocuments;

    public LWSCredentialVerifier(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Verifies what {@code realm} issued, and the documents it hosts, without fetching them from itself
     * (R-26): an {@code iss} that is {@code realm}'s issuer takes its keys from the realm's key store,
     * and a {@code sub} that is one of its {@code lws/cid/{userId}} documents is rendered by
     * {@code documents}, as the endpoint would serve it. Anything else is fetched as before.
     *
     * @param realm     the request's realm, or {@code null} to fetch everything
     * @param documents how the realm's {@code lws/cid} endpoint renders a document
     */
    public LWSCredentialVerifier localTo(ThisRealm realm, CidEndpoint.DocumentRenderer documents) {
        this.thisRealm = realm;
        this.ownDocuments = documents;
        return this;
    }

    public VerificationResult verify(String credential) {
        return verify(credential, null, null);
    }

    /**
     * @param credential       the ID Token
     * @param expectedClientId the relying party's own client identifier. When supplied, {@code aud} must
     *                         contain it, as OpenID Connect Core §3.1.3.7 requires, and {@code azp} must
     *                         equal it — which Core, since errata set 2, only recommends, but the LWS
     *                         suite makes {@code azp} the client identifier. The suite says the JWT
     *                         "MUST be validated as described by OpenID Connect Core Section 3.1.3.7",
     *                         and these rules are what stop a token minted for one relying party being
     *                         replayed at another.
     * @param expectedAudience an additional audience the credential must be restricted to, typically the
     *                         authorization server this verifier speaks for
     */
    public VerificationResult verify(String credential, String expectedClientId, String expectedAudience) {
        VerificationResult result = new VerificationResult();
        result.setTraceId(Trace.newId());
        result.setTokenType(LWSConstants.TOKEN_TYPE_ID_TOKEN);
        try {
            // RFC 7515 §5.2 steps 1-2: strict base64url, so every decoder reads the same header (R-24).
            // Whitespace around the token belongs to the form field, not to the JWS.
            String compact = credential == null ? null : credential.strip();
            boolean wellFormed = JwsChecks.compactSerializationWellFormed(compact);
            result.check("compactSerializationWellFormed", wellFormed);
            if (!wellFormed) {
                result.error("ID Token is not a JWS in compact serialization: three base64url segments, "
                        + "with no padding, whitespace or other characters");
                return result.fail();
            }
            JWSInput jws = new JWSInput(compact);
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

            // An access token is not an ID Token, and must not pass for one (R-05). Keycloak puts
            // "typ": "JWT" in the header of both, so the header cannot tell them apart; the payload's own
            // "typ" claim can — "ID" for an ID Token, "Bearer" or "DPoP" for an access token, "Refresh",
            // "Logout". With this realm's WebID mapper on the access token, an access token carried a
            // WebID sub, iss, azp and exp: everything checked below. A resource server that was handed one
            // could replay it as the user's credential. Other providers rarely set the claim, so its
            // absence is not held against a token; only a type that says it is something else is.
            String payloadType = token.getType();
            boolean isIdToken = payloadType == null || payloadType.isBlank()
                    || TokenUtil.TOKEN_TYPE_ID.equalsIgnoreCase(payloadType.trim());
            result.check("tokenIsIdToken", isIdToken);
            if (!isIdToken) {
                result.error("The token's 'typ' claim says it is not an ID Token");
                return result.fail();
            }

            // RFC 7519 §2: exp, nbf and iat are JSON numbers. "1900000000" read as the same Long (R-24).
            List<String> nonNumericDates = JwsChecks.nonNumericDates(jws.getContent());
            result.check("numericDatesWellFormed", nonNumericDates.isEmpty());
            if (!nonNumericDates.isEmpty()) {
                result.error("ID Token date claims are not JSON numbers: " + nonNumericDates);
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
            // OpenID Connect Core §2: the Issuer Identifier is "a case-sensitive URL using the https
            // scheme that contains scheme, host, and optionally, port number and path components and no
            // query or fragment components". The issuer's configuration and keys are fetched from it, so
            // over plain http anyone on the network path could substitute them (R-07).
            boolean issuerOk = isIssuerIdentifier(iss, SsrfGuard.configuredAllowlist());
            result.check("issuerWellFormed", issuerOk);
            if (!issuerOk) {
                result.error("The 'iss' claim <" + iss + "> is not an https URL without a query or fragment");
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

            // OpenID Connect Core §2 lists 'iat' and 'aud' among the claims an ID Token REQUIRES, and the
            // suite says the token "MUST be validated as described by" Core — so both are required
            // whatever the caller asks for (R-17), as the self-signed suite already required them.
            // Checked here, with the other claims, so a token that cannot be valid costs no fetch.
            Long iat = token.getIat();
            boolean issuedAtPresent = iat != null && iat != 0;
            result.check("issuedAtPresent", issuedAtPresent);
            if (!issuedAtPresent) {
                result.error("ID Token is missing the required 'iat' claim");
                return result.fail();
            }
            boolean issuedAtConsistent = JwsChecks.issuedAtConsistent(token);
            result.check("issuedAtConsistent", issuedAtConsistent);
            if (!issuedAtConsistent) {
                result.error("ID Token 'iat' is in the future, or after its 'exp'");
                return result.fail();
            }
            // A deployment may bound how long a credential lives, so a stolen one ages out (R-28).
            if (ServerSettings.maxCredentialLifetimeSeconds() > 0) {
                boolean lifetimeWithinLimit = JwsChecks.lifetimeWithinLimit(token);
                result.check("lifetimeWithinLimit", lifetimeWithinLimit);
                if (!lifetimeWithinLimit) {
                    result.error("ID Token is valid for longer than this server accepts: 'exp' - 'iat' is over "
                            + ServerSettings.maxCredentialLifetimeSeconds() + " seconds");
                    return result.fail();
                }
            }
            String[] audience = token.getAudience();
            boolean audiencePresent = JwsChecks.audiencePresent(audience);
            result.check("audiencePresent", audiencePresent);
            if (!audiencePresent) {
                result.error("ID Token is missing the required 'aud' claim, or names a blank audience");
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

            // 4. OpenID Connect Discovery -> the keys that may have signed it: every published key the
            //    kid names (or every one, with no kid), published for signing with this alg (R-27).
            List<SigningKey> candidates = resolveSigningKeys(iss, header, result);
            if (candidates == null) {
                return result.fail();
            }

            // 4b. Pin the token's declared algorithm to the discovered key type. Without this a forged
            // token could claim a symmetric alg (e.g. HS256) and have the OP's RSA public key treated
            // as the HMAC secret — the classic algorithm-confusion attack. Candidates of another type
            // were never selected, so this records what selection enforced.
            result.check("algorithmMatchesKey", true);

            // RFC 7518 §3.3: an RSA key "of size 2048 bits or larger MUST be used" (R-27).
            List<SigningKey> strong = candidates.stream().filter(k -> JwsChecks.keyStrongEnough(k.key())).toList();
            result.check("signingKeyStrong", !strong.isEmpty());
            if (strong.isEmpty()) {
                result.error("The key <" + iss + "> published for this ID Token is an RSA key under "
                        + JwsChecks.MIN_RSA_BITS + " bits");
                return result.fail();
            }

            // 5. Signature verification. RFC 7518 §3.4 fixes an ES* signature's length, which Keycloak's
            // ECDSA verifier does not check (R-24).
            if (!JwsChecks.signatureLengthValid(alg, jws.getSignature())) {
                result.check("signatureValid", false);
                result.error("ID Token " + alg + " signature is not the length RFC 7518 requires");
                return result.fail();
            }
            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, alg);
            if (signatureProvider == null) {
                result.check("signatureValid", false);
                result.error("No signature provider available for algorithm " + alg);
                return result.fail();
            }
            // Each candidate in turn: with no kid, or during a rotation that reused one, the first key of
            // the right type is not necessarily the one that signed (R-27).
            boolean signatureValid = false;
            for (SigningKey candidate : strong) {
                KeyWrapper keyWrapper = new KeyWrapper();
                keyWrapper.setKid(header.getKeyId());
                keyWrapper.setAlgorithm(alg);
                keyWrapper.setType(JwsChecks.keycloakKeyType(candidate.key()));
                if (candidate.curve() != null) {
                    keyWrapper.setCurve(candidate.curve());
                }
                keyWrapper.setUse(KeyUse.SIG);
                keyWrapper.setPublicKey(candidate.key());
                SignatureVerifierContext verifierContext = signatureProvider.verifier(keyWrapper);
                if (verifierContext.verify(jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8),
                        jws.getSignature())) {
                    signatureValid = true;
                    break;
                }
            }
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

            // OpenID Connect Core §3.1.3.7: 'aud' MUST contain the relying party's own client_id, and
            // what follows about 'azp' is SHOULD and MAY since errata set 2. Only the caller knows which
            // relying party it is, so the comparison runs when it says — 'client_id' — and the
            // configured or requested 'audience' binds the credential to an authorization server.
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
     * N-Triples and RDF/XML are parsed with Jena RIOT; JSON-LD goes through Jena's JSON-LD processor,
     * with contexts served from this JAR ({@link RdfParsing#parse}), and {@link #modelFromCompactJsonLd}
     * reads it only when its context is not one this provider bundles.
     */
    private Model dereference(String sub, VerificationResult result) {
        try {
            // OutboundHttp applies the SSRF policy, refuses a host that cannot currently be reached, and
            // fetches through a client that resolves only vetted addresses, following up to three
            // redirects, each vetted the same way (R-29). It keeps the breaker's books itself: what
            // happens here after the fetch — a 404, the wrong media type, a document that does not parse
            // — says nothing about the host's health (R-02). The document must still be about sub.
            OutboundHttp.Fetched response = thisRealm == null || ownDocuments == null ? null
                    : thisRealm.document(sub, LWSConstants.RESOURCE_PROVIDER_ID, LWSConstants.CID_PATH, ownDocuments);
            if (response == null) {
                response = OutboundHttp.dereference(sub, RdfParsing.ACCEPT, session);
            }
            if (response.status() != 200) {
                log.debugf("[%s] dereferencing sub <%s> returned HTTP %d", result.getTraceId(), sub,
                        response.status());
                result.check("subjectDereferenced", false);
                result.error("Dereferencing 'sub' <" + sub + "> did not return a controlled identifier document");
                return null;
            }
            String contentType = response.contentType();
            String body = response.body();
            RdfParsing.requireSupported(contentType);
            // CID 1.0: "A controlled identifier document MUST contain an `id` value in the topmost
            // map", and the suite requires that id to equal the subject. For a JSON document that is
            // read from the JSON itself, before any RDF processing (R-18): the graph only shows that
            // *some* node is the subject, which a document about somebody else satisfies by nesting one
            // under alsoKnownAs. An RDF syntax has no topmost map, so there the graph must describe sub.
            boolean json = RdfParsing.isJsonLd(contentType, body);
            boolean describesSubject = !json || sub.equals(RdfParsing.topmostId(body, sub));
            Model model = null;
            if (describesSubject) {
                // JSON-LD is processed properly (Jena + Titanium, contexts served from this JAR) so a
                // conforming document verifies whatever shape it is written in. The compact reader stays
                // as a fallback for a document whose context this provider does not bundle, which is the
                // only interpretation it can offer without having read the term definitions.
                model = RdfParsing.parse(body, contentType, sub);
                if (model == null) {
                    log.debugf("[%s] sub <%s> is JSON-LD this provider cannot process; reading the compact shape",
                            result.getTraceId(), sub);
                    model = modelFromCompactJsonLd(body, sub);
                }
                describesSubject = json
                        || model.contains(model.createResource(sub), null, (org.apache.jena.rdf.model.RDFNode) null);
            }
            // Fetched and read either way: a document about somebody else is a different problem from
            // one that could not be fetched, with a different fix, and is reported as that.
            result.check("subjectDereferenced", true);
            result.check("subjectIdMatches", describesSubject);
            if (!describesSubject) {
                result.error("The document at 'sub' <" + sub + "> is not a controlled identifier document for it");
                return null;
            }
            return model;
        } catch (SsrfGuard.InsecureSchemeException insecure) {
            log.debugf("[%s] sub <%s> is plain http: %s", result.getTraceId(), sub, insecure.getMessage());
            result.check("subjectDereferenced", false);
            result.error("'sub' <" + sub + "> is not an https URL");
            return null;
        } catch (RdfParsing.UnsupportedSyntaxException wrongSyntax) {
            // Distinguished from the generic failure below because it is actionable and gives nothing
            // away: the media type is one the remote server chose to advertise publicly, and naming it
            // is the difference between "your document is not RDF" and "something went wrong".
            log.debugf("[%s] sub <%s> was served as '%s', which is not an RDF syntax this verifier reads",
                    result.getTraceId(), sub, wrongSyntax.getContentType());
            result.check("subjectDereferenced", false);
            result.error("The document at 'sub' <" + sub + "> was served as '" + wrongSyntax.getContentType()
                    + "', which is not an RDF syntax this verifier reads");
            return null;
        } catch (Exception e) {
            // The cause can name the address the host resolved to, so it is logged, not returned.
            log.debugf(e, "[%s] could not dereference or parse sub <%s>", result.getTraceId(), sub);
            result.check("subjectDereferenced", false);
            result.error("Failed to dereference 'sub' <" + sub + "> as a controlled identifier document");
            return null;
        }
    }

    /**
     * Builds a Jena model from a compact JSON-LD controlled identifier document by reading the key
     * names directly, without a JSON-LD processor.
     *
     * <p>This is the <em>fallback</em>, not the normal path. Since P2-1 a document is processed
     * properly by Jena's JSON-LD 1.1 reader (Titanium, relocated into the shaded JAR — the version
     * conflict with Keycloak's copy that this comment used to cite as the reason for hand-rolling was
     * settled by relocation, not avoidance). What is left for this method is the one case the
     * processor cannot handle: a document naming an {@code @context} this provider does not bundle,
     * which {@link RdfParsing#parse} refuses to guess at rather than fetch. Reading the standardized
     * shape by name is the only interpretation available without those term definitions.</p>
     *
     * <p>Handles the shape used by this and other LWS implementations: a subject {@code id} with one
     * or more {@code service} entries each carrying {@code type} and {@code serviceEndpoint}. Exotic
     * JSON-LD framings that remap these terms are not expanded — by construction, since expanding them
     * is precisely what needs the context that was unavailable.</p>
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

        if (!sub.equals(RdfParsing.topmostId(body, sub))) {
            throw new IOException("controlled identifier document 'id' does not equal the subject");
        }
        Resource subject = model.createResource(sub);

        JsonNode services = doc.get("service");
        if (services != null) {
            for (JsonNode svc : services.isArray() ? services : List.of(services)) {
                Resource node = model.createResource();
                // Every type and every endpoint, as the JSON-LD processor would read them: a type array
                // used to read as "" and only the first endpoint counted, so one unbundled context
                // added to an otherwise valid document changed the verdict (R-19).
                JsonNode types = svc.has("type") ? svc.get("type") : svc.get("@type");
                for (String type : strings(types)) {
                    node.addProperty(RDF.type, model.createResource(type));
                }
                for (String endpoint : strings(svc.get("serviceEndpoint"))) {
                    node.addProperty(serviceEndpoint, model.createResource(endpoint));
                }
                subject.addProperty(service, node);
            }
        }
        return model;
    }

    /** The IRIs a value holds: a string, an {@code {"@id": …}} object, or an array of either. */
    private static List<String> strings(JsonNode value) {
        List<String> out = new java.util.ArrayList<>();
        if (value == null) {
            return out;
        }
        for (JsonNode element : value.isArray() ? value : List.of(value)) {
            if (element.isTextual() && !element.asText().isBlank()) {
                out.add(element.asText());
            } else if (element.isObject() && element.path("@id").isTextual()) {
                out.add(element.get("@id").asText());
            }
        }
        return out;
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

    /** A published key that may have signed the token, with its curve when Keycloak needs one (OKP). */
    record SigningKey(PublicKey key, String curve) {
    }

    /**
     * Performs OpenID Connect Discovery on iss and returns the published keys that may have signed the
     * token, or {@code null} after recording why there are none.
     */
    private List<SigningKey> resolveSigningKeys(String iss, JWSHeader header, VerificationResult result) {
        if (thisRealm != null && iss.equals(thisRealm.issuer())) {
            return localSigningKeys(header, result);
        }
        try {
            String base = iss.endsWith("/") ? iss.substring(0, iss.length() - 1) : iss;
            String discoveryUrl = base + "/.well-known/openid-configuration";
            OutboundHttp.Fetched discovery = OutboundHttp.fetch(discoveryUrl, "application/json", session);
            if (discovery.status() != 200) {
                log.debugf("[%s] OpenID discovery for <%s> returned HTTP %d", result.getTraceId(), iss,
                        discovery.status());
                result.check("jwksResolved", false);
                result.error("OpenID Connect Discovery for <" + iss + "> did not return a configuration document");
                return null;
            }
            JsonNode config = JsonSerialization.mapper.readTree(discovery.body());
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
            String alg = header.getRawAlgorithm();
            // Discovery 1.0 §3: id_token_signing_alg_values_supported is the "list of the JWS signing
            // algorithms (alg values) supported by the OP for the ID Token". An ID Token in any other
            // was not signed the way this OP signs them (R-27; Core §3.1.3.7 on the expected alg).
            JsonNode advertised = config.get("id_token_signing_alg_values_supported");
            if (advertised != null && advertised.isArray()) {
                boolean listed = false;
                for (JsonNode value : advertised) {
                    listed |= alg.equals(value.asText(null));
                }
                result.check("algorithmAdvertised", listed);
                if (!listed) {
                    result.error("<" + iss + "> does not list " + alg + " among the algorithms it signs ID Tokens with");
                    return null;
                }
            }
            String jwksUri = text(config, "jwks_uri");
            if (jwksUri == null) {
                result.check("jwksResolved", false);
                result.error("The OpenID configuration for <" + iss + "> has no jwks_uri");
                return null;
            }
            OutboundHttp.Fetched jwks = OutboundHttp.fetch(jwksUri, "application/jwk-set+json, application/json", session);
            if (jwks.status() != 200) {
                log.debugf("[%s] the JWKS for <%s> returned HTTP %d", result.getTraceId(), iss, jwks.status());
                result.check("jwksResolved", false);
                result.error("The JWK set published by <" + iss + "> could not be retrieved");
                return null;
            }
            String kid = header.getKeyId();
            List<SigningKey> candidates = candidateKeys(JsonSerialization.mapper.readTree(jwks.body()), kid, alg);
            if (candidates.isEmpty() && kid != null && jwks.cached()) {
                // A kid the cached set does not have may be a key the issuer has just rotated in: ask again,
                // at most every REFETCH_INTERVAL_MS, so made-up kids cannot make every token cost a fetch.
                OutboundHttp.Fetched fresh = OutboundHttp.refetch(jwksUri, "application/jwk-set+json, application/json",
                        session);
                if (fresh != null && fresh.status() == 200) {
                    candidates = candidateKeys(JsonSerialization.mapper.readTree(fresh.body()), kid, alg);
                }
            }
            result.check("jwksResolved", !candidates.isEmpty());
            if (candidates.isEmpty()) {
                result.error("No JWK published by <" + iss + "> matched the token (kid=" + kid + ", alg=" + alg + ")");
                return null;
            }
            return candidates;
        } catch (SsrfGuard.InsecureSchemeException insecure) {
            // iss itself has been checked, so this is the jwks_uri, which OpenID Connect Discovery 1.0
            // §3 says "MUST use the https scheme".
            log.debugf("[%s] the jwks_uri for <%s> is plain http: %s", result.getTraceId(), iss, insecure.getMessage());
            result.check("jwksResolved", false);
            result.error("The OpenID configuration for <" + iss + "> names a jwks_uri that is not an https URL");
            return null;
        } catch (Exception e) {
            log.debugf(e, "[%s] OpenID Connect discovery failed for <%s>", result.getTraceId(), iss);
            result.check("jwksResolved", false);
            result.error("OpenID Connect Discovery failed for <" + iss + ">");
            return null;
        }
    }

    /**
     * This realm's own keys that may have signed one of its ID Tokens: what discovery and its JWK set
     * would have produced, without the three loopback requests (R-26). The realm is its own issuer, so
     * there is no configuration whose {@code issuer} could disagree.
     */
    private List<SigningKey> localSigningKeys(JWSHeader header, VerificationResult result) {
        String kid = header.getKeyId();
        String alg = header.getRawAlgorithm();
        result.check("issuerDiscoveryMatches", true);
        List<SigningKey> candidates = thisRealm.keys()
                .filter(key -> KeyUse.SIG.equals(key.getUse()) && key.getStatus() != null && key.getStatus().isEnabled())
                .filter(key -> kid == null || kid.equals(key.getKid()))
                .filter(key -> alg.equals(key.getAlgorithmOrDefault()))
                .filter(key -> key.getPublicKey() instanceof PublicKey publicKey && JwsChecks.algMatchesKey(alg, publicKey))
                .map(key -> new SigningKey((PublicKey) key.getPublicKey(), key.getCurve()))
                .toList();
        result.check("jwksResolved", !candidates.isEmpty());
        if (candidates.isEmpty()) {
            result.error("This realm has no enabled signing key that matched the token (kid=" + kid + ", alg=" + alg + ")");
            return null;
        }
        return candidates;
    }

    /**
     * The keys of a JWK set that may have signed a token with {@code kid} and {@code alg} (R-27):
     *
     * <ul>
     *   <li>the {@code kid}'s keys, or — with no {@code kid} — every key, all to be tried. OpenID Connect
     *       Core §10.1 requires a {@code kid} when the set has several keys, but the first key of the
     *       right type, which is all this used to try, is not the one that signed halfway through a
     *       rotation;</li>
     *   <li>published for signing: {@code use} absent or {@code sig}, {@code key_ops} absent or
     *       including {@code verify}, and {@code alg} absent or the token's. A {@code use: enc} key used
     *       to verify signatures;</li>
     *   <li>of a type and curve that {@code alg} is ({@link JwsChecks#algMatchesKey}), and, for Ed25519, a
     *       key only its holder can sign for ({@link JwsChecks#edwardsKeyProblem}).</li>
     * </ul>
     *
     * <p>A key that cannot be read — {@code oct}, a curve this server does not support, garbage — is
     * skipped. It used to throw, and abort the whole set.</p>
     */
    static List<SigningKey> candidateKeys(JsonNode jwks, String kid, String alg) {
        List<SigningKey> out = new java.util.ArrayList<>();
        JsonNode keys = jwks == null ? null : jwks.get("keys");
        if (keys == null || !keys.isArray()) {
            return out;
        }
        for (JsonNode node : keys) {
            if (!node.isObject()) {
                continue;
            }
            if (kid != null && !kid.equals(node.path("kid").asText(null))) {
                continue;
            }
            String use = node.path("use").asText(null);
            String keyAlg = node.path("alg").asText(null);
            if ((use != null && !"sig".equals(use)) || (keyAlg != null && !keyAlg.equals(alg))
                    || !JwsChecks.keyOpsAllowVerify(node) || JwsChecks.edwardsKeyProblem(node) != null) {
                continue;
            }
            PublicKey key;
            try {
                key = JWKParser.create(JsonSerialization.mapper.treeToValue(node, JWK.class)).toPublicKey();
            } catch (Exception unreadable) {
                continue;
            }
            if (key != null && JwsChecks.algMatchesKey(alg, key)) {
                out.add(new SigningKey(key, "OKP".equals(node.path("kty").asText(null))
                        ? node.path("crv").asText(null) : null));
            }
        }
        return out;
    }

    /**
     * True iff {@code iss} is an Issuer Identifier as OpenID Connect Core §2 defines one: an absolute URL
     * with a host, optionally a port and path, and no user information, query or fragment — https, or
     * plain http only to a host this deployment allow-lists ({@link SsrfGuard#secureOrAllowListed}).
     */
    static boolean isIssuerIdentifier(String iss, Set<String> allowedHosts) {
        URI uri;
        try {
            uri = new URI(iss);
        } catch (URISyntaxException malformed) {
            return false;
        }
        return !uri.isOpaque() && uri.getHost() != null && uri.getRawUserInfo() == null
                && uri.getRawQuery() == null && uri.getRawFragment() == null
                && SsrfGuard.secureOrAllowListed(uri.getScheme(), uri.getHost(), allowedHosts);
    }

    private static String text(JsonNode node, String field) {
        return node != null && node.hasNonNull(field) ? node.get(field).asText() : null;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
