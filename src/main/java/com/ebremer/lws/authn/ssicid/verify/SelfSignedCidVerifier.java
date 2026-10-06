/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Validates a self-issued JWT as an LWS authentication credential, per
 * https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/
 *
 * Algorithm:
 *   1. Reject alg == "none", and any critical header this provider does not implement.
 *   2. The credential is self-issued: sub == iss == client_id (the controlled identifier).
 *   3. Dereference 'sub' to a controlled identifier document whose 'id' equals 'sub'. An HTTPS URI is
 *      fetched; a DID is resolved to its DID document — did:key locally, did:web over HTTPS — which
 *      DID 1.1 §5 defines as an extension of a controlled identifier document, and which the suite
 *      says "is designed to work with".
 *   4. Select, by the JWT 'kid', a verification method the subject's 'authentication' relationship
 *      names (embedded or by reference, CID 1.0 §2.3.1 and §3.3), controlled by the subject, of type
 *      JsonWebKey (publicKeyJwk) or Multikey (publicKeyMultibase), and neither revoked nor expired.
 *   5. Validate the JWT signature against that key (RFC 7515 §5.2), with the algorithm pinned to the
 *      key type.
 *   6. Ensure the token carries iat and exp, is not expired, and is restricted to the target audience.
 *
 * RDF parsing of the (possibly arbitrary-syntax) controlled identifier document uses Apache Jena;
 * the JWK itself is JSON, so key extraction is JSON-native. A DID document is read with the JSON rules
 * of its own representation instead (see resolveDid).
 */
package com.ebremer.lws.authn.ssicid.verify;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.ebremer.lws.authn.did.DidKey;
import com.ebremer.lws.authn.did.Dids;
import com.ebremer.lws.authn.config.ServerSettings;
import com.ebremer.lws.authn.jose.JwsChecks;
import com.ebremer.lws.authn.jose.JwsSignatures;
import com.ebremer.lws.authn.jose.KeyIdFragment;
import com.ebremer.lws.authn.jose.PublicJwk;
import com.ebremer.lws.authn.net.OutboundHttp;
import com.ebremer.lws.authn.net.SsrfGuard;
import com.ebremer.lws.authn.rdf.RdfParsing;
import com.ebremer.lws.authn.verify.Trace;
import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.logging.Logger;
import org.apache.jena.query.ParameterizedSparqlString;
import org.apache.jena.query.QueryExecution;
import org.apache.jena.query.QueryExecutionFactory;
import org.apache.jena.query.QuerySolution;
import org.apache.jena.query.ResultSet;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.StmtIterator;
import org.apache.jena.vocabulary.RDF;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.ssicid.SsiCidConstants;
import com.ebremer.lws.authn.verify.ReplayCache;

/**
 * @author Erich Bremer
 */
public class SelfSignedCidVerifier {

    private static final Logger log = Logger.getLogger(SelfSignedCidVerifier.class);

    private final KeycloakSession session;
    private final ReplayCache replayCache;

    /**
     * @param session the Keycloak session, used for outbound fetches and for Keycloak's own signature
     *                providers. May be {@code null} outside Keycloak (unit tests): then only a subject
     *                that needs no fetch — a {@code did:key} — can be verified, and signatures are
     *                checked with the JDK.
     */
    public SelfSignedCidVerifier(KeycloakSession session) {
        this(session, null);
    }

    /**
     * @param replayCache optional, and normally {@code null}. See {@link ReplayCache}: a verify
     *                    endpoint is asked about the same live credential repeatedly, so refusing a
     *                    second look is only correct for a caller that treats one verification as one
     *                    use.
     */
    public SelfSignedCidVerifier(KeycloakSession session, ReplayCache replayCache) {
        this.session = session;
        this.replayCache = replayCache;
    }

    public SsiCidVerificationResult verify(String credential) {
        return verify(credential, null);
    }

    /**
     * @param credential       the self-issued JWT
     * @param expectedAudience the authorization server this verifier speaks for. The suite says the
     *                         {@code aud} claim "MUST include the target authorization server", which
     *                         only means anything if the verifier knows which one it is; without it the
     *                         credential is not valid (R-16).
     */
    public SsiCidVerificationResult verify(String credential, String expectedAudience) {
        SsiCidVerificationResult result = new SsiCidVerificationResult();
        result.setTraceId(Trace.newId());
        result.setTokenType(SsiCidConstants.TOKEN_TYPE_JWT);
        try {
            // RFC 7515 §5.2 steps 1-2: strict base64url, so every decoder reads the same header (R-24).
            // Whitespace around the token belongs to the form field, not to the JWS.
            String compact = credential == null ? null : credential.strip();
            boolean wellFormed = JwsChecks.compactSerializationWellFormed(compact);
            result.check("compactSerializationWellFormed", wellFormed);
            if (!wellFormed) {
                result.error("Credential is not a JWS in compact serialization: three base64url segments, "
                        + "with no padding, whitespace or other characters");
                return result.fail();
            }
            JWSInput jws = new JWSInput(compact);
            JWSHeader header = jws.getHeader();
            JsonWebToken token = JsonSerialization.readValue(jws.getContent(), JsonWebToken.class);

            String sub = token.getSubject();
            String iss = token.getIssuer();
            String clientId = asString(token.getOtherClaims().get("client_id"));
            result.setSubject(sub);

            // 1. alg must not be "none"
            String alg = header.getRawAlgorithm();
            boolean algOk = alg != null && !"none".equalsIgnoreCase(alg);
            result.check("signingAlgorithmNotNone", algOk);
            if (!algOk) {
                result.error("Credential MUST NOT use 'none' as the signing algorithm");
                return result.fail();
            }

            // RFC 7515 5.2, cited normatively by this suite: reject critical headers we do not implement.
            List<String> critical = JwsChecks.criticalHeaders(jws);
            result.check("noUnsupportedCriticalHeaders", critical.isEmpty());
            if (!critical.isEmpty()) {
                result.error("Credential carries unsupported critical header parameters: " + critical);
                return result.fail();
            }

            boolean typeOk = JwsChecks.typeIsJwtOrAbsent(header.getType());
            result.check("typeIsJwt", typeOk);
            if (!typeOk) {
                result.error("Credential 'typ' header is not a JWT type");
                return result.fail();
            }

            // RFC 7519 §2: exp, nbf and iat are JSON numbers. "1900000000" read as the same Long (R-24).
            List<String> nonNumericDates = JwsChecks.nonNumericDates(jws.getContent());
            result.check("numericDatesWellFormed", nonNumericDates.isEmpty());
            if (!nonNumericDates.isEmpty()) {
                result.error("Credential date claims are not JSON numbers: " + nonNumericDates);
                return result.fail();
            }

            // 2. self-issued: sub == iss == client_id
            boolean selfIssued = sub != null && !sub.isBlank() && sub.equals(iss) && sub.equals(clientId);
            result.check("selfIssued", selfIssued);
            if (!selfIssued) {
                result.error("Claims 'sub', 'iss' and 'client_id' MUST all use the same URI "
                        + "(sub=" + sub + ", iss=" + iss + ", client_id=" + clientId + ")");
                return result.fail();
            }
            result.setClient(clientId);

            // "The verifier MUST use the `kid` (key id) value from the signed JWT header to identify a
            // verification method." Falling back to "the only key" when there is no kid would make the
            // selection the verifier's guess rather than the credential's assertion.
            String kid = header.getKeyId();
            boolean kidPresent = kid != null && !kid.isBlank();
            result.check("keyIdPresent", kidPresent);
            if (!kidPresent) {
                result.error("Credential header is missing the 'kid' used to select a verification method");
                return result.fail();
            }

            // 3-4. dereference the subject and select the verification method by kid
            List<VerificationMethod> methods = Dids.isDid(sub) ? resolveDid(sub, result) : dereference(sub, result);
            if (methods == null) {
                return result.fail();
            }
            VerificationMethod method = selectByKid(methods, kid);
            boolean keyFound = method != null;
            result.check("verificationMethodFound", keyFound);
            if (!keyFound) {
                result.error("No JsonWebKey or Multikey verification method in the 'authentication' relationship of <"
                        + sub + ">, controlled by it, matched kid=" + kid);
                return result.fail();
            }

            // CID 1.0 §2.2: a revoked method "MUST NOT be used", and a verifier is "expected to not verify
            // any proofs associated with" a method at or after its expiry.
            String inactive = method.inactiveReason(Instant.now());
            result.check("verificationMethodActive", inactive == null);
            if (inactive != null) {
                result.error("The verification method " + (method.id() == null ? "named by kid=" + kid
                        : "<" + method.id() + ">") + " " + inactive);
                return result.fail();
            }
            JsonNode jwk = method.publicKeyJwk();

            // 5. validate the signature against the selected key
            PublicKey publicKey = method.publicKey() != null ? method.publicKey() : toPublicKey(jwk);

            // Pin the declared algorithm to the key actually published. Without this a forged token
            // could claim a symmetric alg (HS256) and have the subject's public key treated as the HMAC
            // secret. It fails closed inside Keycloak today, but only by accident of how the provider
            // reacts to a PublicKey where it wants a SecretKey — which is not a security guarantee.
            boolean algMatchesKey = JwsChecks.algMatchesKey(alg, publicKey);
            result.check("algorithmMatchesKey", algMatchesKey);
            if (!algMatchesKey) {
                result.error("Credential 'alg' " + alg + " is not consistent with the published "
                        + publicKey.getAlgorithm() + " verification method");
                return result.fail();
            }

            // The JWK's own metadata must agree too: a key published for encryption, or declaring a
            // different algorithm, is not a key this signature may be checked against. (A Multikey has
            // no such metadata of its own; its key type alone decides, and its derived JWK carries the
            // one algorithm that key type signs with.)
            String jwkUse = jwk.path("use").asText(null);
            String jwkAlg = jwk.path("alg").asText(null);
            boolean jwkUsable = (jwkUse == null || "sig".equals(jwkUse)) && (jwkAlg == null || jwkAlg.equals(alg))
                    && JwsChecks.keyOpsAllowVerify(jwk);
            result.check("verificationMethodUsableForSigning", jwkUsable);
            if (!jwkUsable) {
                result.error("The selected verification method is not published for signing with " + alg);
                return result.fail();
            }

            // RFC 7518 §3.3: an RSA key "of size 2048 bits or larger MUST be used" (R-27).
            boolean keyStrong = JwsChecks.keyStrongEnough(publicKey);
            result.check("signingKeyStrong", keyStrong);
            if (!keyStrong) {
                result.error("The selected verification method is an RSA key under " + JwsChecks.MIN_RSA_BITS + " bits");
                return result.fail();
            }

            // RFC 7518 §3.4 fixes an ES* signature's length, which Keycloak's ECDSA verifier does not
            // check, so an over-long signature verified here but not on the JDK path (R-24).
            if (!JwsChecks.signatureLengthValid(alg, jws.getSignature())) {
                result.check("signatureValid", false);
                result.error("Credential " + alg + " signature is not the length RFC 7518 requires");
                return result.fail();
            }
            boolean signatureValid;
            if (session == null) {
                signatureValid = JwsSignatures.verify(alg, publicKey, jws);
            } else {
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
                if (KeyType.OKP.equals(keyWrapper.getType())) {
                    keyWrapper.setCurve(jwk.path("crv").asText("Ed25519"));
                }
                keyWrapper.setUse(KeyUse.SIG);
                keyWrapper.setPublicKey(publicKey);
                signatureValid = signatureProvider.verifier(keyWrapper).verify(
                        jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8), jws.getSignature());
            }
            result.check("signatureValid", signatureValid);
            if (!signatureValid) {
                result.error("Credential signature is invalid");
                return result.fail();
            }

            // 6. expiry (and not-before) window. The credential MUST carry an 'exp': Keycloak's
            // isActive() treats a missing exp as "never expires", which would let a captured
            // self-issued JWT be replayed forever ('aud' bounds where it may be used, not for how long).
            Long exp = token.getExp();
            boolean notExpired = JwsChecks.withinValidityWindow(token);
            result.check("notExpired", notExpired);
            if (!notExpired) {
                result.error(exp == null || exp == 0
                        ? "Credential is missing the required 'exp' claim"
                        : "Credential is expired or not yet valid");
                return result.fail();
            }

            // "The JWT MUST include an `iat` (issued at) claim." Without it there is no lower bound on
            // the credential's age, so a stolen token's provenance cannot be reasoned about at all.
            Long iat = token.getIat();
            boolean issuedAtPresent = iat != null && iat != 0;
            result.check("issuedAtPresent", issuedAtPresent);
            if (!issuedAtPresent) {
                result.error("Credential is missing the required 'iat' claim");
                return result.fail();
            }
            boolean issuedAtConsistent = JwsChecks.issuedAtConsistent(token);
            result.check("issuedAtConsistent", issuedAtConsistent);
            if (!issuedAtConsistent) {
                result.error("Credential 'iat' is in the future, or after its 'exp'");
                return result.fail();
            }
            // A deployment may bound how long a credential lives, so a stolen one ages out (R-28).
            if (ServerSettings.maxCredentialLifetimeSeconds() > 0) {
                boolean lifetimeWithinLimit = JwsChecks.lifetimeWithinLimit(token);
                result.check("lifetimeWithinLimit", lifetimeWithinLimit);
                if (!lifetimeWithinLimit) {
                    result.error("Credential is valid for longer than this server accepts: 'exp' - 'iat' is over "
                            + ServerSettings.maxCredentialLifetimeSeconds() + " seconds");
                    return result.fail();
                }
            }

            // "The `aud` claim MUST include the target authorization server." Every conforming credential
            // names its target, so requiring the match rejects none of them — and without it a credential
            // minted for authorization server A was accepted on behalf of B, the replay the requirement
            // exists to stop (R-16). With no target to compare against, there is no verdict to give.
            String[] aud = token.getAudience();
            boolean audiencePresent = JwsChecks.audiencePresent(aud);
            result.check("audiencePresent", audiencePresent);
            if (!audiencePresent) {
                result.error("Credential is missing the required 'aud' claim, or names a blank audience");
                return result.fail();
            }
            boolean audienceMatched = expectedAudience != null && !expectedAudience.isBlank()
                    && JwsChecks.audienceIncludes(aud, expectedAudience);
            result.check("audienceMatched", audienceMatched);
            if (!audienceMatched) {
                result.error(expectedAudience == null || expectedAudience.isBlank()
                        ? "No target authorization server was given to match 'aud' against"
                        : "Credential 'aud' does not include the target audience <" + expectedAudience + ">");
                return result.fail();
            }

            if (replayCache != null) {
                boolean firstSighting = replayCache.firstSighting(iss, token.getId());
                result.check("notReplayed", firstSighting);
                if (!firstSighting) {
                    result.error("Credential 'jti' has already been verified within the replay window");
                    return result.fail();
                }
            }

            result.setValid(result.getErrors().isEmpty());
        } catch (Exception e) {
            // Never echo the exception to the caller: it can name internal hosts, ports and library
            // internals. The detail goes to the log under the result's trace id.
            log.debugf(e, "[%s] LWS self-signed CID credential verification failed", result.getTraceId());
            result.error("Credential could not be validated");
            return result.fail();
        }
        return result;
    }

    /** Dereferences an HTTP(S) subject and returns the verification methods its CID document offers. */
    private List<VerificationMethod> dereference(String sub, SsiCidVerificationResult result) {
        try {
            // OutboundHttp applies the SSRF policy, refuses a host that cannot currently be reached, and
            // fetches through a client that follows no redirects and resolves only vetted addresses. It
            // keeps the breaker's books itself: what happens here after the fetch — a 404, the wrong
            // media type, a document that does not parse — says nothing about the host's health (R-02).
            OutboundHttp.Fetched response = OutboundHttp.fetch(sub, RdfParsing.ACCEPT, session);
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
            // The suite requires "a valid controlled identifier document with an `id` value equal to the
            // subject identifier". For a JSON document that is the topmost map's id, read from the JSON
            // itself (R-18); an RDF syntax has no topmost map, so there the graph must describe sub.
            boolean json = RdfParsing.isJsonLd(contentType, body);
            if (json && !sub.equals(RdfParsing.topmostId(body, sub))) {
                throw new SubjectIdMismatchException();
            }
            // Processed as real JSON-LD where possible, so a conforming document from another
            // implementation works regardless of how it spells things; the compact reader remains for
            // a document naming a context this provider does not bundle.
            Model model = RdfParsing.parse(body, contentType, sub);
            List<VerificationMethod> methods;
            if (model != null) {
                if (!json && !model.contains(model.createResource(sub), null, (RDFNode) null)) {
                    throw new SubjectIdMismatchException();
                }
                methods = collectFromRdf(model, sub);
            } else {
                log.debugf("[%s] sub <%s> is JSON-LD this provider cannot process; reading the compact shape",
                        result.getTraceId(), sub);
                methods = collectFromJsonLd(body, sub);
            }
            result.check("subjectDereferenced", true);
            result.check("subjectIdMatches", true);
            return methods;
        } catch (SubjectIdMismatchException wrongDocument) {
            // A document was fetched and read; it is just not this subject's. Reported as that, not as a
            // failure to dereference, which is a different problem with a different fix.
            result.check("subjectDereferenced", true);
            result.check("subjectIdMatches", false);
            result.error("The document at 'sub' <" + sub + "> is not a controlled identifier document for it");
            return null;
        } catch (SsrfGuard.InsecureSchemeException insecure) {
            // The suite works with "subject identifiers that use HTTPS URIs as well as DID URIs"; over
            // plain http anyone on the network path could substitute the subject's keys (R-07).
            log.debugf("[%s] sub <%s> is plain http: %s", result.getTraceId(), sub, insecure.getMessage());
            result.check("subjectDereferenced", false);
            result.error("'sub' <" + sub + "> is neither an https URL nor a DID");
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
     * Resolves a DID subject to its DID document and returns the verification methods it offers.
     *
     * <p>A DID document is read with the JSON rules of its representation, not through a JSON-LD
     * processor: {@code did:key} documents are generated here and never parsed, and the did:web method
     * expects documents to be served as plain JSON. The DID 1.1 JSON-LD context is not bundled — DID 1.1
     * is a Candidate Recommendation and its context is not yet published at a stable URL — so a JSON-LD
     * processor could not read a DID 1.1 document anyway, and the structure the reader relies on
     * ({@code id}, {@code authentication}, {@code verificationMethod}, {@code type},
     * {@code controller}, key material) is fixed by DID 1.1 and CID 1.0 rather than by the context.</p>
     */
    private List<VerificationMethod> resolveDid(String sub, SsiCidVerificationResult result) {
        JsonNode document;
        try {
            String method = Dids.methodOf(sub);
            document = switch (method) {
                case Dids.METHOD_KEY -> Dids.didKeyDocument(sub);
                case Dids.METHOD_WEB -> fetchDidWebDocument(sub, Dids.didWebUrl(sub), result);
                default -> throw new Dids.UnsupportedDidMethodException(method);
            };
        } catch (IllegalArgumentException unresolvable) {
            // An invalid DID, an unsupported method, or a did:key that is not canonically encoded. The
            // message names the rule broken and nothing about this server.
            result.check("subjectDereferenced", false);
            result.error("'sub' <" + sub + "> could not be resolved: " + unresolvable.getMessage());
            return null;
        }
        if (document == null) {
            return null; // fetchDidWebDocument recorded why
        }
        result.check("subjectDereferenced", true);
        try {
            List<VerificationMethod> methods = collectFromJson(document, sub);
            result.check("subjectIdMatches", true);
            return methods;
        } catch (IOException mismatch) {
            // did:web, Read: "Verify that the ID of the resolved DID document matches the Web DID being
            // resolved." The same rule is the suite's own: the document's id must equal the subject.
            result.check("subjectIdMatches", false);
            result.error("The DID document resolved for 'sub' <" + sub + "> does not have that DID as its 'id'");
            return null;
        }
    }

    /**
     * Fetches a did:web document from {@code url} through the SSRF-guarded client. The did:web method
     * requires HTTPS, and {@link Dids#didWebUrl} only ever produces {@code https:} URLs.
     *
     * @return the document, or {@code null} after recording why there is none
     */
    private JsonNode fetchDidWebDocument(String did, String url, SsiCidVerificationResult result) {
        try {
            OutboundHttp.Fetched response = OutboundHttp.fetch(url, Dids.DID_DOCUMENT_ACCEPT, session);
            if (response.status() != 200) {
                log.debugf("[%s] resolving <%s> via %s returned HTTP %d", result.getTraceId(), did, url,
                        response.status());
                result.check("subjectDereferenced", false);
                result.error("Resolving 'sub' <" + did + "> did not return a DID document");
                return null;
            }
            String contentType = response.contentType();
            if (!Dids.isDidDocumentMediaType(contentType)) {
                result.check("subjectDereferenced", false);
                result.error("The DID document for 'sub' <" + did + "> was served as '"
                        + contentType.split(";")[0].trim() + "', which is not a DID document media type");
                return null;
            }
            JsonNode document = JsonSerialization.mapper.readTree(response.body());
            if (document == null || !document.isObject()) {
                result.check("subjectDereferenced", false);
                result.error("Resolving 'sub' <" + did + "> did not return a DID document");
                return null;
            }
            return document;
        } catch (Exception e) {
            // As for an HTTPS subject: the cause can describe this server's network, so it is logged.
            log.debugf(e, "[%s] could not resolve <%s> via %s", result.getTraceId(), did, url);
            result.check("subjectDereferenced", false);
            result.error("Failed to resolve 'sub' <" + did + "> to a DID document");
            return null;
        }
    }

    // ---- key extraction (static + side-effect free, so it is unit-testable without a session) ----

    /**
     * A verification method the subject may authenticate with, read from its controlled identifier
     * document.
     *
     * @param id           the method's own identifier, absolute ({@code <subject>#<fragment>} by
     *                     convention). The readers refuse a method without one (CID 1.0 §2.2)
     * @param publicKeyJwk its public key as a JWK: the {@code publicKeyJwk} of a {@code JsonWebKey}, or
     *                     the JWK a {@code Multikey}'s {@code publicKeyMultibase} decodes to
     * @param type         {@code JsonWebKey} or {@code Multikey}
     * @param publicKey    the decoded key, when the reader already has it (a Multikey); otherwise
     *                     {@code null} and the key is built from {@code publicKeyJwk}
     * @param revoked      CID 1.0 {@code revoked}, or {@code null}
     * @param expires      CID 1.0 {@code expires}, or {@code null}
     */
    public record VerificationMethod(String id, JsonNode publicKeyJwk, String type, PublicKey publicKey,
                                     Instant revoked, Instant expires) {

        /** A {@code JsonWebKey} method with no revocation or expiry. */
        public VerificationMethod(String id, JsonNode publicKeyJwk) {
            this(id, publicKeyJwk, SsiCidConstants.TYPE_JSON_WEB_KEY, null, null, null);
        }

        /** Why this method may not be used at {@code now}, or {@code null} if it may. */
        public String inactiveReason(Instant now) {
            if (revoked != null && !now.isBefore(revoked)) {
                return "was revoked at " + revoked;
            }
            if (expires != null && !now.isBefore(expires)) {
                return "expired at " + expires;
            }
            return null;
        }
    }

    /** The document's {@code id} is not the subject: it is not evidence about the subject. */
    public static final class SubjectIdMismatchException extends IOException {
        public SubjectIdMismatchException() {
            super("controlled identifier document 'id' does not equal the subject");
        }
    }

    /** Parses a compact JSON-LD (or plain JSON) document and delegates to {@link #collectFromJson}. */
    public static List<VerificationMethod> collectFromJsonLd(String body, String sub) throws IOException {
        return collectFromJson(JsonSerialization.mapper.readTree(body), sub);
    }

    /**
     * Collects the verification methods a document's {@code authentication} relationship names, read
     * from the compact shape the CID and DID JSON representations share.
     *
     * <ul>
     *   <li>The document's {@code id} must equal {@code sub}: CID 1.0 requires an {@code id} in the
     *       topmost map, and a document that does not claim to describe this subject is not evidence
     *       about it.</li>
     *   <li>Only methods associated with {@code authentication} count, "either by reference (URL) or by
     *       value (object)" (CID 1.0 §3.3). CID 1.0 §2.3: "Verification methods that are not associated
     *       with a particular verification relationship cannot be used for that verification
     *       relationship" — so a key listed under {@code verificationMethod} alone, perhaps meant for
     *       key agreement or assertions, is not one the subject authenticates with. A reference is
     *       resolved within this document (CID 1.0 §3.4); it is not followed to another one.</li>
     *   <li>Each method must have an identifier, in the subject's document (CID 1.0 §2.2, §3.3), and be
     *       controlled by the subject — a document may embed methods controlled by someone else, and
     *       those are not keys this subject may authenticate with.</li>
     *   <li>One {@code type}: {@code JsonWebKey} with a {@code publicKeyJwk}, or {@code Multikey} with a
     *       {@code publicKeyMultibase} — the two types CID 1.0 defines — and not both key properties. A
     *       method publishing private key material, or a key this provider cannot decode, is not a
     *       conforming verification method and is skipped.</li>
     * </ul>
     *
     * @throws SubjectIdMismatchException if the document's {@code id} is not {@code sub}
     * @throws IOException                if the document is not a JSON object
     */
    public static List<VerificationMethod> collectFromJson(JsonNode doc, String sub) throws IOException {
        if (doc == null || !doc.isObject()) {
            throw new IOException("controlled identifier document is not a JSON object");
        }
        // Resolved as RdfParsing.topmostId resolves it, so both paths agree on what the id is.
        String id = RdfParsing.resolveReference(firstText(doc, "id", "@id"), sub);
        if (id == null || !id.equals(sub)) {
            throw new SubjectIdMismatchException();
        }
        List<VerificationMethod> out = new ArrayList<>();
        JsonNode authentication = doc.get("authentication");
        if (authentication == null || authentication.isNull()) {
            return out;
        }
        Set<String> seen = new HashSet<>();
        Map<String, JsonNode> byId = null;
        for (JsonNode entry : authentication.isArray() ? authentication : List.of(authentication)) {
            JsonNode method = null;
            if (entry.isTextual()) {
                String reference = RdfParsing.resolveReference(entry.asText(), id);
                if (reference != null) {
                    if (byId == null) {
                        byId = indexById(doc, id);
                    }
                    method = byId.get(reference);
                }
            } else if (entry.isObject()) {
                method = entry;
            }
            if (method == null) {
                continue; // unresolvable here, or a reference to a method in another document
            }
            toVerificationMethod(method, sub, id).ifPresent(vm -> {
                if (seen.add(vm.id())) {
                    out.add(vm);
                }
            });
        }
        return out;
    }

    /** Reads one verification method map; empty if it is not one the subject may authenticate with. */
    private static Optional<VerificationMethod> toVerificationMethod(JsonNode method, String sub, String base) {
        String methodId = RdfParsing.resolveReference(firstText(method, "id", "@id"), base);
        // CID 1.0 §2.2: a verification method "MUST include id, type, controller", each one value, and
        // "MUST NOT contain multiple verification material properties". A method without an id was
        // selectable by its JWK's kid, which §3.3 — retrieval by the method's identifier — never is; one
        // with two types, or two keys, leaves it to the reader which applies (R-23). A type or controller
        // written as an array of one is the same single value to a JSON-LD processor, and is read as one.
        if (methodId == null) {
            log.debugf("skipping a verification method of <%s> that has no id", sub);
            return Optional.empty();
        }
        String type = soleText(method, "type", "@type");
        String controller = RdfParsing.resolveReference(soleText(method, "controller"), base);
        if (type == null || !sub.equals(controller) || !inSubjectsDocument(methodId, sub)) {
            return Optional.empty();
        }
        if (method.has("publicKeyJwk") && method.has("publicKeyMultibase")) {
            log.debugf("skipping verification method <%s>: it has more than one verification material property",
                    methodId);
            return Optional.empty();
        }
        Instant revoked;
        Instant expires;
        try {
            revoked = soleDateTime(method, "revoked");
            expires = soleDateTime(method, "expires");
        } catch (DateTimeParseException | IllegalArgumentException malformed) {
            // An unreadable revocation date is not evidence that the key was never revoked.
            log.debugf("skipping verification method <%s>: 'revoked'/'expires' is not one xsd:dateTimeStamp", methodId);
            return Optional.empty();
        }
        if (SsiCidConstants.TYPE_JSON_WEB_KEY.equals(type)) {
            JsonNode jwk = method.get("publicKeyJwk");
            return fromJwk(methodId, jwk, revoked, expires);
        }
        if (SsiCidConstants.TYPE_MULTIKEY.equals(type)) {
            return fromMultibase(methodId, firstText(method, "publicKeyMultibase"), revoked, expires);
        }
        return Optional.empty();
    }

    private static Optional<VerificationMethod> fromJwk(String methodId, JsonNode jwk, Instant revoked, Instant expires) {
        if (jwk == null || !jwk.isObject()) {
            return Optional.empty();
        }
        // CID 1.0 §2.2.3: the publicKeyJwk map "MUST NOT include any members of the private information
        // class, such as d". A document that publishes one has leaked a private key, and the method is
        // not a conforming verification method.
        List<String> privateMembers = PublicJwk.privateMembers(jwk);
        if (!privateMembers.isEmpty()) {
            log.debugf("skipping verification method <%s>: its publicKeyJwk carries private members %s",
                    methodId, privateMembers);
            return Optional.empty();
        }
        // An Ed25519 key must be one only its holder can sign for: canonical, on the curve, not of small
        // order. The JDK accepts the identity point, against which any message verifies (R-27).
        String weakEd25519 = JwsChecks.ed25519Problem(jwk);
        if (weakEd25519 != null) {
            log.debugf("skipping verification method <%s>: %s", methodId, weakEd25519);
            return Optional.empty();
        }
        return Optional.of(new VerificationMethod(methodId, jwk, SsiCidConstants.TYPE_JSON_WEB_KEY, null,
                revoked, expires));
    }

    private static Optional<VerificationMethod> fromMultibase(String methodId, String multibase,
                                                              Instant revoked, Instant expires) {
        if (multibase == null) {
            return Optional.empty();
        }
        try {
            DidKey.DecodedKey key = DidKey.decodeMultibase(multibase);
            JsonNode jwk = JsonSerialization.mapper.valueToTree(DidKey.toJwk(key));
            return Optional.of(new VerificationMethod(methodId, jwk, SsiCidConstants.TYPE_MULTIKEY,
                    key.publicKey(), revoked, expires));
        } catch (IllegalArgumentException unusable) {
            log.debugf("skipping Multikey verification method <%s>: %s", methodId, unusable.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Collects the subject's verification methods via Jena/SPARQL. The subject is bound as an IRI
     * parameter (never concatenated) so it cannot inject SPARQL, and the query itself requires the
     * method to be named by the subject's {@code authentication} relationship, to be a
     * {@code JsonWebKey} or {@code Multikey}, and to be controlled by the subject.
     *
     * <p>In RDF, embedding a method under {@code authentication} and referencing one defined under
     * {@code verificationMethod} produce the same {@code sec:authenticationMethod} triple, so requiring
     * that triple is exactly "associated with the relationship by value or by reference".</p>
     */
    public static List<VerificationMethod> collectFromRdf(Model model, String sub) {
        // Only each method and its type are selected; its values are then read one property at a time.
        // Selecting them here as OPTIONALs, as this once did, returned the cross product of every value
        // of every one of them, and a method that failed to decode was decoded again on every row: a
        // 36 KiB document with one bad key and a few hundred revoked/expiration values took 271 seconds,
        // growing with the square of the document's size (R-03).
        ParameterizedSparqlString pss = new ParameterizedSparqlString();
        pss.setCommandText("SELECT DISTINCT ?m ?type WHERE { "
                + "?sub ?authentication ?m . ?m a ?type ; ?controller ?sub . "
                + "FILTER(?type = ?jsonWebKey || ?type = ?multikey) }");
        pss.setIri("sub", sub);
        pss.setIri("authentication", SsiCidConstants.SEC_AUTHENTICATION);
        pss.setIri("jsonWebKey", SsiCidConstants.JSON_WEB_KEY_TYPE);
        pss.setIri("multikey", SsiCidConstants.MULTIKEY_TYPE);
        pss.setIri("controller", SsiCidConstants.SEC_CONTROLLER);
        Property publicKeyJwk = model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_JWK);
        Property publicKeyMultibase = model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_MULTIBASE);
        Property controllerProperty = model.createProperty(SsiCidConstants.SEC_CONTROLLER);
        Property revokedProperty = model.createProperty(SsiCidConstants.SEC_REVOKED);
        Property expirationProperty = model.createProperty(SsiCidConstants.SEC_EXPIRATION);

        List<VerificationMethod> out = new ArrayList<>();
        Set<String> accepted = new HashSet<>();
        try (QueryExecution qe = QueryExecutionFactory.create(pss.asQuery(), model)) {
            ResultSet rs = qe.execSelect();
            while (rs.hasNext()) {
                QuerySolution row = rs.next();
                Resource node = row.getResource("m");
                String key = node.toString();
                if (accepted.contains(key)) {
                    continue; // already read: named by authentication more than once
                }
                // A blank node is a method with no id (CID 1.0 §2.2), and is refused like one (R-23).
                String methodId = node.isURIResource() ? node.getURI() : null;
                if (!inSubjectsDocument(methodId, sub)) {
                    continue;
                }
                // One type, one controller, one kind of key material (CID 1.0 §2.2, R-23). The query found
                // a JsonWebKey or Multikey type and the subject among the controllers; neither may share.
                if (count(node, RDF.type) != 1 || count(node, controllerProperty) != 1
                        || (node.hasProperty(publicKeyJwk) && node.hasProperty(publicKeyMultibase))) {
                    log.debugf("skipping verification method <%s>: more than one type, controller or key", methodId);
                    continue;
                }
                Optional<VerificationMethod> method;
                try {
                    Instant revoked = dateTimeStamp(soleLiteral(node, revokedProperty));
                    Instant expires = dateTimeStamp(soleLiteral(node, expirationProperty));
                    if (SsiCidConstants.JSON_WEB_KEY_TYPE.equals(row.getResource("type").getURI())) {
                        String jwk = soleLiteral(node, publicKeyJwk);
                        method = jwk == null ? Optional.empty()
                                : fromJwk(methodId, JsonSerialization.mapper.readTree(jwk), revoked, expires);
                    } else {
                        method = fromMultibase(methodId, soleLiteral(node, publicKeyMultibase), revoked, expires);
                    }
                } catch (IOException | RuntimeException unusable) {
                    // An unreadable revocation date is not evidence that the key was never revoked, and
                    // two values for one property leave it undecided which applies — including a
                    // revocation and an expiry the reader would otherwise have picked one of at random.
                    log.debugf("skipping verification method <%s>: %s", methodId, unusable.getMessage());
                    continue;
                }
                if (method.isPresent()) {
                    accepted.add(key);
                    out.add(method.get());
                }
            }
        }
        return out;
    }

    /** How many values {@code node} has for {@code property}. */
    private static int count(Resource node, Property property) {
        StmtIterator values = node.listProperties(property);
        try {
            int n = 0;
            while (values.hasNext()) {
                values.next();
                n++;
            }
            return n;
        } finally {
            values.close();
        }
    }

    /**
     * The lexical form of {@code method}'s one value for {@code property}, or {@code null} if it has
     * none.
     *
     * @throws IllegalArgumentException if it has more than one, or one that is not a literal
     */
    private static String soleLiteral(Resource method, Property property) {
        StmtIterator values = method.listProperties(property);
        try {
            if (!values.hasNext()) {
                return null;
            }
            RDFNode value = values.next().getObject();
            if (values.hasNext()) {
                throw new IllegalArgumentException("more than one value for <" + property.getURI() + ">");
            }
            if (!value.isLiteral()) {
                throw new IllegalArgumentException("<" + property.getURI() + "> is not a literal");
            }
            return value.asLiteral().getLexicalForm();
        } finally {
            values.close();
        }
    }

    /**
     * Picks the method the JWT's {@code kid} names. In order:
     *
     * <ol>
     *   <li>by the method's full identifier — the verification method identifier CID 1.0 §3.3
     *       retrieves by, and the usual {@code kid} for a DID ({@code did:key:z…#z…}). Every candidate
     *       is already a method of the subject's own document, so an exact match can never reach into
     *       another document;</li>
     *   <li>by the fragment of the method's {@code id}, which is where CID 1.0 conventionally puts it
     *       ({@code <subject>#<kid>}), a leading {@code #} on the {@code kid} allowed — the method a
     *       relative reference {@code #<kid>} resolves to under CID 1.0 §3.4;</li>
     *   <li>by the JWK's own {@code kid}, for a method whose id does not carry it.</li>
     * </ol>
     *
     * <p>The JWK's {@code kid} used to come second. When one method's JWK {@code kid} was another
     * method's fragment, the {@code kid} picked the first method where §3.4 names the second, and the
     * credential failed (R-23).</p>
     *
     * <p>There is no fallback to "the only key": the credential says which key signed it, and
     * honouring that is the point of the check.</p>
     *
     * <p>The fragment is compared both raw and percent-decoded: a {@code kid} is arbitrary text, so any
     * document that puts one in an IRI fragment has to encode it (this provider does — see
     * {@link KeyIdFragment}), and a comparison that only looked at the raw fragment would fail to find
     * the very method the credential names.</p>
     */
    public static VerificationMethod selectByKid(List<VerificationMethod> methods, String kid) {
        if (methods.isEmpty() || kid == null || kid.isBlank()) {
            return null;
        }
        for (VerificationMethod method : methods) {
            if (kid.equals(method.id())) {
                return method;
            }
        }
        String wanted = kid.startsWith("#") ? kid.substring(1) : kid;
        for (VerificationMethod method : methods) {
            String id = method.id();
            int hash = id == null ? -1 : id.lastIndexOf('#');
            if (hash < 0) {
                continue;
            }
            String fragment = id.substring(hash + 1);
            if (wanted.equals(fragment) || wanted.equals(KeyIdFragment.decode(fragment))) {
                return method;
            }
        }
        for (VerificationMethod method : methods) {
            if (kid.equals(method.publicKeyJwk().path("kid").asText(null))) {
                return method;
            }
        }
        return null;
    }

    /** Builds a public key from a JWK JSON object. */
    public static PublicKey toPublicKey(JsonNode jwkNode) throws IOException {
        JWK jwk = JsonSerialization.readValue(jwkNode.toString(), JWK.class);
        return JWKParser.create(jwk).toPublicKey();
    }

    // ---- small helpers ----

    /**
     * True iff a method identifier is a fragment of the subject's own document.
     *
     * <p>CID 1.0 §3.3 takes the document a method lives in from the method's identifier — the URL
     * without its fragment — and requires that document's {@code id}, and the method's
     * {@code controller}, to be that URL. Here the document is always the subject's, so a method whose
     * identifier names a different document is one that §3.3 would have gone and fetched from there,
     * not accepted from here. A method with no identifier is not one §3.3 can retrieve at all (R-23).</p>
     *
     * <p>Document is compared with document, not with the subject as written: a subject identifier
     * may itself carry a fragment — a Solid-style WebID such as {@code https://alice.example/card#me}
     * — and its keys ({@code …/card#key-1}) are still in its document.</p>
     */
    private static boolean inSubjectsDocument(String methodId, String sub) {
        return methodId != null && documentOf(methodId).equals(documentOf(sub));
    }

    /** An identifier without its fragment: the document it names. */
    private static String documentOf(String identifier) {
        int hash = identifier.indexOf('#');
        return hash >= 0 ? identifier.substring(0, hash) : identifier;
    }

    /**
     * Every map in {@code document} that has an {@code id}, by that id resolved against {@code base}; the
     * first in document order wins, as a search from the top would find it.
     *
     * <p>Built once per document. Searching the whole document again for every reference in
     * {@code authentication} made resolution cost the number of references times the size of the
     * document: a 163&nbsp;KiB DID document of 8&nbsp;000 references that resolve to nothing took 30
     * seconds (R-03). The walk keeps its own stack rather than recursing, so nesting depth costs no
     * thread stack either.</p>
     */
    private static Map<String, JsonNode> indexById(JsonNode document, String base) {
        Map<String, JsonNode> byId = new HashMap<>();
        Deque<JsonNode> pending = new ArrayDeque<>();
        pending.push(document);
        while (!pending.isEmpty()) {
            JsonNode node = pending.pop();
            if (node.isObject()) {
                String resolved = RdfParsing.resolveReference(firstText(node, "id", "@id"), base);
                if (resolved != null) {
                    byId.putIfAbsent(resolved, node);
                }
            }
            if (node.isContainerNode() && node.size() > 0) {
                List<JsonNode> children = new ArrayList<>(node.size());
                node.elements().forEachRemaining(children::add);
                for (int i = children.size() - 1; i >= 0; i--) {
                    pending.push(children.get(i)); // reversed, so the first child is visited first
                }
            }
        }
        return byId;
    }

    /**
     * The one string the first of {@code names} present on {@code node} holds — a string, or an array of
     * exactly one — or {@code null} if it holds none, several, or something else.
     */
    private static String soleText(JsonNode node, String... names) {
        for (String name : names) {
            JsonNode value = node.get(name);
            if (value == null) {
                continue;
            }
            if (value.isArray() && value.size() == 1) {
                value = value.get(0);
            }
            return value.isTextual() ? value.asText() : null;
        }
        return null;
    }

    /** The first of {@code names} present on {@code node} as a string, or {@code null}. */
    private static String firstText(JsonNode node, String... names) {
        for (String name : names) {
            JsonNode value = node.get(name);
            if (value != null && value.isTextual()) {
                return value.asText();
            }
        }
        return null;
    }

    /**
     * The one date-time a method's {@code revoked} or {@code expires} gives, or {@code null} if it has
     * none.
     *
     * <p>A string, as CID 1.0 writes it; or the shapes JSON-LD gives the same single value — a value
     * object ({@code {"@value": "…", "@type": "xsd:dateTime"}}) or an array of one. {@code null} is no
     * value, as it is to a JSON-LD processor. Anything else fails rather than reading as "no date": this
     * used to look for a string and, finding a value object, an array of two dates or a number instead,
     * report the key as never revoked (R-06). The RDF path applies the same rule through
     * {@link #soleLiteral}.</p>
     *
     * @throws IllegalArgumentException if present and not exactly one string
     * @throws DateTimeParseException   if that string is not an {@code xsd:dateTimeStamp}
     */
    private static Instant soleDateTime(JsonNode method, String name) {
        JsonNode value = method.get(name);
        if (value == null || value.isNull()) {
            return null;
        }
        if (value.isArray() && value.size() == 1) {
            value = value.get(0);
        }
        if (value.isObject() && value.has("@value")) {
            value = value.get("@value");
        }
        if (!value.isTextual()) {
            throw new IllegalArgumentException("'" + name + "' is not one date-time string");
        }
        return dateTimeStamp(value.asText());
    }

    /** An {@code xsd:dateTimeStamp} (a date-time with a time zone), or {@code null} if absent. */
    private static Instant dateTimeStamp(String value) {
        return value == null ? null : OffsetDateTime.parse(value.trim()).toInstant();
    }

    private static String asString(Object value) {
        return value == null ? null : value.toString();
    }
}
