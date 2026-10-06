/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Validates a signed SAML 2.0 assertion as an LWS authentication credential, per
 * https://w3c.github.io/lws-protocol/lws10-authn-saml/
 *
 * Hardening:
 *   - XXE: the XML is parsed with a locally-configured, DTD-disallowing parser (not the caller's).
 *   - XML Signature Wrapping (XSW): every signature present follows SAML Core §5.4 — one Reference,
 *     to the signed element's own ID, and no transform that could leave content out — and is
 *     validated; claims are then read ONLY from the one assertion, by precise direct-child navigation —
 *     never a document-wide getElementsByTagName that an injected element could win.
 *
 * Trust is out of band (the verifier is given the IdP certificate). Signatures are validated with the
 * JDK's XML Digital Signature API (SamlSignatures), against that certificate's key alone.
 */
package com.ebremer.lws.authn.saml.verify;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.jboss.logging.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.ebremer.lws.authn.saml.SamlConstants;
import com.ebremer.lws.authn.verify.Trace;

/**
 * @author Erich Bremer
 */
public class SamlCredentialVerifier {

    private static final Logger log = Logger.getLogger(SamlCredentialVerifier.class);

    /** Shared with the JWT suites, so one deployment does not apply two different tolerances. */
    private static long clockSkewSeconds() {
        return com.ebremer.lws.authn.jose.JwsChecks.clockSkewSeconds();
    }
    private static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String NS = SamlConstants.SAML_ASSERTION_NS;
    private static final String PROTOCOL_NS = SamlConstants.SAML_PROTOCOL_NS;

    /** The SAML version this verifier implements, and the only one it processes (SAML Core §4.1.2). */
    private static final String SAML_VERSION = "2.0";

    /** The only {@code <samlp:StatusCode>} an authentication credential may carry (SAML Core §3.2.2). */
    private static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

    /** SAML Core §8.3.6: the NameID format of an entity — the only one an Issuer may carry. */
    private static final String ENTITY_FORMAT = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

    /** The confirmation method an LWS credential uses: it is a bearer token. */
    private static final String BEARER_METHOD = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

    /**
     * @param credential       the SAML 2.0 Response, as XML or base64-encoded XML
     * @param idpCertificate   the trusted IdP signing certificate (established out of band)
     * @param expectedAudience optional audience the assertion must be restricted to
     */
    public SamlVerificationResult verify(String credential, X509Certificate idpCertificate, String expectedAudience) {
        return verify(credential, idpCertificate, expectedAudience, false);
    }

    /**
     * @param credential              the SAML 2.0 Response, as XML or base64-encoded XML
     * @param idpCertificate          the trusted IdP signing certificate (established out of band)
     * @param expectedAudience        optional audience the assertion must be restricted to
     * @param allowExpiredCertificate accept a signing certificate that is expired or not yet valid.
     *                                Only for offline analysis of an old credential; never in a
     *                                deployment that treats the result as a live authentication.
     */
    public SamlVerificationResult verify(String credential, X509Certificate idpCertificate, String expectedAudience,
                                         boolean allowExpiredCertificate) {
        return verify(credential, SamlTrust.certificate(idpCertificate), expectedAudience, null, null,
                allowExpiredCertificate);
    }

    /**
     * @param credential              the SAML 2.0 Response, as XML or base64-encoded XML
     * @param trust                   the IdP certificates trusted for the assertion's issuer (established
     *                                out of band): one the caller supplied, or the realm's SAML identity
     *                                providers'
     * @param expectedAudience        optional audience every {@code <AudienceRestriction>} must name
     * @param expectedIssuer          optional {@code <Issuer>} the assertion must name
     * @param expectedRecipient       optional bearer {@code Recipient} — the LWS client identifier — the
     *                                assertion must name
     * @param allowExpiredCertificate accept a signing certificate that is expired or not yet valid.
     *                                Only for offline analysis of an old credential; never in a
     *                                deployment that treats the result as a live authentication.
     */
    public SamlVerificationResult verify(String credential, SamlTrust trust, String expectedAudience,
                                         String expectedIssuer, String expectedRecipient,
                                         boolean allowExpiredCertificate) {
        SamlVerificationResult result = new SamlVerificationResult();
        result.setTraceId(Trace.newId());
        result.setTokenType(SamlConstants.TOKEN_TYPE_SAML2);
        try {
            Document doc = parseSecurely(toXmlBytes(credential));

            // --- the Response and its one assertion ---
            // Located by position, never by a document-wide search an injected element could win: the
            // document is a Response holding exactly one Assertion, or an Assertion. A second assertion
            // beside the signed one — the signature-wrapping shape — leaves no single "the" credential.
            Element root = doc.getDocumentElement();
            Element response = null;
            Element assertion;
            if (isElement(root, PROTOCOL_NS, "Response")) {
                response = root;
                // A <samlp:Response> that reports a failure is not a credential, however well signed the
                // assertion it happens to carry is.
                boolean success = isSuccessStatus(response);
                result.check("statusSuccess", success);
                if (!success) {
                    result.error("SAML Response <StatusCode> is not " + STATUS_SUCCESS);
                    return result.fail();
                }
                List<Element> assertions = children(response, NS, "Assertion");
                if (assertions.size() != 1) {
                    result.check("singleAssertion", false);
                    result.error("A Response must contain exactly one Assertion, found " + assertions.size());
                    return result.fail();
                }
                assertion = assertions.get(0);
            } else if (isElement(root, NS, "Assertion")) {
                assertion = root;
            } else {
                result.error("The credential is neither a SAML Response nor a SAML Assertion");
                return result.fail();
            }

            // SAML Core §4.1.2: a relying party "MUST NOT process any assertion with a major assertion
            // version number not supported by the relying party", and §4.1.3.3 has assertions "appear only
            // in response messages of the same major version". Version="3.0" used to verify (R-22).
            boolean versionSupported = SAML_VERSION.equals(assertion.getAttribute("Version"))
                    && (response == null || SAML_VERSION.equals(response.getAttribute("Version")));
            result.check("versionSupported", versionSupported);
            if (!versionSupported) {
                result.error("The credential is not SAML " + SAML_VERSION);
                return result.fail();
            }

            // --- signatures (SAML Core §5.4) ---
            // The profile covers "the <ds:Signature> elements found directly within SAML assertions,
            // requests, and responses", and Profiles §4.1.4.3 says to "Verify any signatures present on
            // the assertion(s) or the response". So each one present is checked, and at least one must be:
            // a signed Response covers the assertion inside it (Core §5.3). Only the Response's signature
            // used to be checked when it had one, so an assertion signed by some other key went unread.
            List<Element> signedElements = new ArrayList<>();
            List<Element> signatures = new ArrayList<>();
            for (Element element : response == null ? List.of(assertion) : List.of(response, assertion)) {
                List<Element> own = children(element, XMLDSIG_NS, "Signature");
                if (own.size() > 1) {
                    result.check("signatureCoversSignedElement", false);
                    result.error("<" + element.getLocalName() + "> carries more than one <ds:Signature>");
                    return result.fail();
                }
                if (own.size() == 1) {
                    signedElements.add(element);
                    signatures.add(own.get(0));
                }
            }
            result.check("signaturePresent", !signatures.isEmpty());
            if (signatures.isEmpty()) {
                result.error("Credential is not signed (no enveloped XML signature on the Response or Assertion)");
                return result.fail();
            }
            // The profile first, from the parsed signatures, before any cryptography: one reference, to
            // the signed element's own ID (§5.4.2), and only the transforms and algorithms allowed. A
            // signature whose XPath transform left <Subject> out verified — and then the subject could be
            // replaced (R-22).
            String coverage = null;
            String algorithms = null;
            for (int i = 0; i < signatures.size(); i++) {
                XMLSignature parsed = SamlSignatures.read(signatures.get(i), signedElements.get(i));
                coverage = coverage != null ? coverage : SamlSignatures.coverageProblem(parsed, signedElements.get(i));
                algorithms = algorithms != null ? algorithms : SamlSignatures.algorithmProblem(parsed);
            }
            result.check("signatureCoversSignedElement", coverage == null);
            if (coverage != null) {
                result.error("Signature does not cover exactly the signed element (SAML Core §5.4.2): " + coverage);
                return result.fail();
            }
            result.check("signatureAlgorithmsAllowed", algorithms == null);
            if (algorithms != null) {
                result.error("Signature is outside SAML Core §5.4's profile: " + algorithms);
                return result.fail();
            }

            // --- trust (R-25) ---
            // The certificates trusted for the issuer the assertion names: asked before the signature is
            // known good, because the answer decides which keys may check it. Nothing else of the
            // assertion is read until one of them has.
            Element claimedIssuer = firstChild(assertion, NS, "Issuer");
            List<SamlTrust.TrustedCertificate> candidates =
                    trust.certificatesFor(claimedIssuer == null ? null : claimedIssuer.getTextContent().trim());
            result.check("trustedCertificateFound", !candidates.isEmpty());
            if (candidates.isEmpty()) {
                result.error("No certificate is trusted to sign for the assertion's <Issuer>: no enabled SAML "
                        + "identity provider of this realm has it as its entity ID");
                return result.fail();
            }
            // Each certificate in turn — an IdP may have several while it rotates keys — skipping one that
            // is not a trust anchor: expired or not yet valid, which would keep a retired key usable
            // forever, or holding a key an XML-DSig provider would verify as readily as any other at
            // 512 bits (R-22). The first that every signature validates against is the one.
            SamlTrust.TrustedCertificate chosen = null;
            boolean anyExpired = false;
            boolean anyWeak = false;
            boolean anyTried = false;
            for (SamlTrust.TrustedCertificate candidate : candidates) {
                X509Certificate certificate = candidate.certificate();
                if (SamlSignatures.keyProblem(certificate.getPublicKey()) != null) {
                    anyWeak = true;
                    continue;
                }
                if (!certificateCurrentlyValid(certificate) && !allowExpiredCertificate) {
                    anyExpired = true;
                    continue;
                }
                anyTried = true;
                boolean all = true;
                for (int i = 0; i < signatures.size() && all; i++) {
                    all = SamlSignatures.validate(signatures.get(i), signedElements.get(i), certificate.getPublicKey());
                }
                if (all) {
                    chosen = candidate;
                    break;
                }
            }
            if (chosen == null) {
                if (anyTried) {
                    result.check("signatureValid", false);
                    result.error(candidates.size() == 1
                            ? "XML signature is not valid for the " + describe(candidates.get(0))
                            : "XML signature is not valid for any certificate trusted for the issuer");
                } else if (anyExpired) {
                    result.check("certificateValid", false);
                    result.error(candidates.size() == 1
                            ? "The " + describe(candidates.get(0)) + " is expired or not yet valid"
                            : "No certificate trusted for the issuer is both current and strong enough");
                } else {
                    result.check("certificateKeyStrong", false);
                    result.error(candidates.size() == 1
                            ? "The " + describe(candidates.get(0)) + " holds "
                                    + SamlSignatures.keyProblem(candidates.get(0).certificate().getPublicKey())
                            : "Every certificate trusted for the issuer holds a key too weak to trust");
                }
                return result.fail();
            }
            result.check("certificateValid", certificateCurrentlyValid(chosen.certificate()));
            result.check("certificateKeyStrong", true);
            result.check("signatureValid", true);
            result.setTrustSource(chosen.source());
            result.setIdentityProvider(chosen.identityProvider());
            result.setCertificateSha256(sha256Fingerprint(chosen.certificate()));

            // --- claims, read only from the covered assertion ---

            Element subject = onlyChild(assertion, "Subject", result);
            if (subject == null) {
                return result.fail();
            }
            Element nameId = onlyChild(subject, "NameID", result);
            if (nameId == null) {
                return result.fail();
            }
            String subjectValue = nameId.getTextContent().trim();
            result.setSubject(subjectValue);
            result.setSubjectFormat(attr(nameId, "Format"));
            if (subjectValue.isEmpty()) {
                result.error("Assertion <NameID> subject is empty");
                return result.fail();
            }
            // LWS core §4.1: the subject "MUST be a URI". A bare name ("alice"), an email address or a
            // transient handle identifies someone only to this IdP, and is not an LWS subject (R-20).
            boolean subjectIsUri = isAbsoluteUri(subjectValue);
            result.check("subjectIsUri", subjectIsUri);
            if (!subjectIsUri) {
                result.error("Assertion <NameID> is not a URI, which an LWS subject must be");
                return result.fail();
            }

            // "The SAML token MUST use the `saml:Issuer` assertion for the LWS issuer identifier", and
            // LWS core §4.1 makes the issuer a REQUIRED claim. Recording it without requiring it would
            // let a credential through with no identified issuing party at all.
            Element issuer = firstChild(assertion, NS, "Issuer");
            String issuerValue = issuer == null ? null : issuer.getTextContent().trim();
            result.setIssuer(issuerValue);
            boolean issuerPresent = issuerValue != null && !issuerValue.isEmpty();
            result.check("issuerPresent", issuerPresent);
            if (!issuerPresent) {
                result.error("The verified assertion has no <Issuer>");
                return result.fail();
            }
            // LWS core §4.1: the issuer "MUST be a URI". SAML Profiles §4.1.4.2: its Format "MUST be
            // omitted or have a value of urn:oasis:names:tc:SAML:2.0:nameid-format:entity" — an Issuer
            // in any other format is not naming an entity at all (R-20).
            String issuerFormat = attr(issuer, "Format");
            boolean issuerWellFormed = isAbsoluteUri(issuerValue) && isEntityFormat(issuerFormat);
            result.check("issuerWellFormed", issuerWellFormed);
            if (!issuerWellFormed) {
                result.error("The assertion's <Issuer> is not an entity URI");
                return result.fail();
            }
            // SAML Profiles §4.1.4.2: a Response's <Issuer> "MAY be omitted, but if present it MUST
            // contain the unique identifier of the issuing identity provider" — the one the assertion
            // names. A Response from one IdP around another's assertion used to verify (R-22).
            if (response != null) {
                Element responseIssuer = firstChild(response, NS, "Issuer");
                boolean issuersMatch = responseIssuer == null
                        || (issuerValue.equals(responseIssuer.getTextContent().trim())
                            && isEntityFormat(attr(responseIssuer, "Format")));
                result.check("issuersMatch", issuersMatch);
                if (!issuersMatch) {
                    result.error("The Response's <Issuer> is not the assertion's");
                    return result.fail();
                }
            }

            // The issuer the caller expects, when it says: a caller-supplied certificate is otherwise bound
            // to no issuer at all (R-25).
            if (expectedIssuer != null && !expectedIssuer.isBlank()) {
                boolean issuerMatched = expectedIssuer.trim().equals(issuerValue);
                result.check("issuerMatched", issuerMatched);
                if (!issuerMatched) {
                    result.error("The assertion's <Issuer> is not the expected <" + expectedIssuer.trim() + ">");
                    return result.fail();
                }
            }

            // IssueInstant is required on both (SAML Core §2.3.3, §3.2.2), and one in the future was not
            // written by a clock keeping time: an IssueInstant in 2099 used to verify (R-22).
            boolean issueInstantValid = notInFuture(attr(assertion, "IssueInstant"))
                    && (response == null || notInFuture(attr(response, "IssueInstant")));
            result.check("issueInstantValid", issueInstantValid);
            if (!issueInstantValid) {
                result.error("IssueInstant is missing, unreadable, or in the future");
                return result.fail();
            }

            // --- subject confirmation (the bearer window and the LWS client identifier) ---
            // The suite carries the LWS client identifier in SubjectConfirmationData/@Recipient, and the
            // Web Browser SSO profile bounds a bearer subject with its own NotOnOrAfter. Neither is
            // implied by <Conditions>, so both are enforced here. Exactly one SubjectConfirmation is
            // required: with several there is no single "the" client identifier to report.
            Element confirmation = onlyChild(subject, "SubjectConfirmation", result);
            if (confirmation == null) {
                return result.fail();
            }
            boolean bearer = BEARER_METHOD.equals(confirmation.getAttribute("Method"));
            result.check("bearerSubjectConfirmation", bearer);
            if (!bearer) {
                result.error("<SubjectConfirmation> Method must be " + BEARER_METHOD);
                return result.fail();
            }
            Element scd = firstChild(confirmation, NS, "SubjectConfirmationData");
            if (scd == null) {
                result.check("recipientPresent", false);
                result.error("<SubjectConfirmation> has no <SubjectConfirmationData>");
                return result.fail();
            }
            String recipient = scd.getAttribute("Recipient");
            boolean recipientPresent = recipient != null && !recipient.isBlank();
            result.check("recipientPresent", recipientPresent);
            if (!recipientPresent) {
                result.error("<SubjectConfirmationData> has no Recipient (the LWS client identifier)");
                return result.fail();
            }
            result.setRecipient(recipient);
            result.setClient(recipient); // the suite puts the LWS client identifier in Recipient
            // SAML Profiles §4.1.4.3: "Verify that the Recipient attribute in any bearer
            // <SubjectConfirmationData> matches" where it was delivered. Only the caller knows that, and
            // it can now say (R-25; the half of P1-M2 that was never done).
            if (expectedRecipient != null && !expectedRecipient.isBlank()) {
                boolean recipientMatched = expectedRecipient.trim().equals(recipient);
                result.check("recipientMatched", recipientMatched);
                if (!recipientMatched) {
                    result.error("<SubjectConfirmationData> Recipient is not the expected <"
                            + expectedRecipient.trim() + ">");
                    return result.fail();
                }
            }

            String scdNotOnOrAfter = attr(scd, "NotOnOrAfter");
            if (scdNotOnOrAfter == null || scdNotOnOrAfter.isBlank()) {
                result.check("subjectConfirmationWithinWindow", false);
                result.error("<SubjectConfirmationData> has no NotOnOrAfter expiry (required for a bearer subject)");
                return result.fail();
            }
            boolean confirmationCurrent = withinValidity(attr(scd, "NotBefore"), scdNotOnOrAfter);
            result.check("subjectConfirmationWithinWindow", confirmationCurrent);
            if (!confirmationCurrent) {
                result.error("<SubjectConfirmationData> is outside its NotBefore/NotOnOrAfter window");
                return result.fail();
            }

            // --- conditions (SAML Core §2.5.1) ---
            // At most one <Conditions> — the schema allows one, and only the first used to be read — and
            // every condition in it one this verifier understands. §2.5.1.1: a condition that is not
            // understood makes the assertion Indeterminate, and "An assertion that is determined to be
            // Invalid or Indeterminate MUST be rejected" (R-21).
            List<Element> allConditions = children(assertion, NS, "Conditions");
            Element conditions = allConditions.isEmpty() ? null : allConditions.get(0);
            String notUnderstood = allConditions.size() > 1 ? "the assertion has more than one <Conditions>"
                    : conditionsProblem(conditions);
            result.check("conditionsUnderstood", notUnderstood == null);
            if (notUnderstood != null) {
                result.error("Assertion <Conditions> cannot be evaluated: " + notUnderstood);
                return result.fail();
            }
            // §2.5.1.5: a OneTimeUse assertion "SHOULD be used immediately by the relying party and MUST NOT
            // be retained for future use". This verifier retains nothing; the caller is told, so that it
            // does not either.
            if (firstChild(conditions, NS, "OneTimeUse") != null) {
                result.setOneTimeUse(Boolean.TRUE);
            }

            // --- validity window ---
            String notBefore = attr(conditions, "NotBefore");
            String notOnOrAfter = attr(conditions, "NotOnOrAfter");
            result.setNotBefore(notBefore);
            result.setNotOnOrAfter(notOnOrAfter);
            // The assertion MUST carry an expiry. Without Conditions/@NotOnOrAfter there is no upper
            // time bound at all, so a captured assertion could be replayed indefinitely.
            if (notOnOrAfter == null || notOnOrAfter.isBlank()) {
                result.check("withinValidityWindow", false);
                result.error("Assertion has no <Conditions> NotOnOrAfter expiry (required)");
                return result.fail();
            }
            boolean within = withinValidity(notBefore, notOnOrAfter);
            result.check("withinValidityWindow", within);
            if (!within) {
                result.error("Assertion is outside its validity window (NotBefore=" + notBefore
                        + ", NotOnOrAfter=" + notOnOrAfter + ")");
                return result.fail();
            }

            // --- audience ---
            // §2.5.1.4: several <AudienceRestriction>s "each MUST be evaluated independently" and form a
            // conjunction — the assertion is for an audience only if every restriction names it. They used
            // to be pooled, so [app] AND [elsewhere] passed for app (R-21).
            List<List<String>> restrictions = audienceRestrictions(conditions);
            List<String> audiences = restrictions.stream().flatMap(List::stream).distinct().toList();
            result.setAudiences(audiences);
            if (expectedAudience != null && !expectedAudience.isBlank()) {
                boolean matched = !restrictions.isEmpty()
                        && restrictions.stream().allMatch(restriction -> restriction.contains(expectedAudience));
                result.check("audienceMatched", matched);
                if (!matched) {
                    result.error("Expected audience <" + expectedAudience
                            + "> is not in every <AudienceRestriction> of the assertion");
                    return result.fail();
                }
            } else {
                boolean present = !restrictions.isEmpty();
                result.check("audiencePresent", present);
                if (!present) {
                    result.error("Assertion has no <AudienceRestriction>");
                    return result.fail();
                }
            }

            result.setValid(result.getErrors().isEmpty());
        } catch (Exception e) {
            // Parser and XML-DSig exceptions can carry file paths and library internals; log, don't echo.
            log.debugf(e, "[%s] LWS SAML credential verification failed", result.getTraceId());
            result.error("Credential could not be validated");
            return result.fail();
        } catch (StackOverflowError tooDeep) {
            // A last resort: MAX_ELEMENT_DEPTH should stop any document deep enough to get here (R-09).
            // The stack has unwound by now, and nothing the verifier holds outlives the call.
            log.debugf("[%s] LWS SAML credential verification overflowed the stack", result.getTraceId());
            result.error("Credential could not be validated");
            return result.fail();
        }
        return result;
    }

    /** True iff {@code certificate} is inside its own validity period right now. */
    private static boolean certificateCurrentlyValid(X509Certificate certificate) {
        if (certificate == null) {
            return false;
        }
        try {
            certificate.checkValidity();
            return true;
        } catch (java.security.cert.CertificateExpiredException
                | java.security.cert.CertificateNotYetValidException e) {
            return false;
        }
    }

    /** How an error names a trusted certificate. */
    private static String describe(SamlTrust.TrustedCertificate trusted) {
        return trusted.identityProvider() == null ? "supplied IdP certificate"
                : "certificate of identity provider '" + trusted.identityProvider() + "'";
    }

    /**
     * The certificate's SHA-256 fingerprint, as {@code openssl x509 -noout -fingerprint -sha256} prints
     * it — colon-separated uppercase hex — so a caller can compare it with the certificate it meant.
     */
    static String sha256Fingerprint(X509Certificate certificate) throws Exception {
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        StringBuilder out = new StringBuilder(digest.length * 3);
        for (byte b : digest) {
            if (out.length() > 0) {
                out.append(':');
            }
            out.append(String.format("%02X", b));
        }
        return out.toString();
    }

    /** True iff a {@code <samlp:Response>} reports {@code …:status:Success}. */
    private static boolean isSuccessStatus(Element response) {
        Element status = firstChild(response, PROTOCOL_NS, "Status");
        Element code = status == null ? null : firstChild(status, PROTOCOL_NS, "StatusCode");
        return code != null && STATUS_SUCCESS.equals(code.getAttribute("Value"));
    }

    private static boolean isElement(Element element, String ns, String local) {
        return element != null && local.equals(element.getLocalName()) && ns.equals(element.getNamespaceURI());
    }

    /** True iff an Issuer {@code Format} is absent or the entity format (SAML Profiles §4.1.4.2). */
    private static boolean isEntityFormat(String format) {
        return format == null || ENTITY_FORMAT.equals(format.trim());
    }

    /** True iff {@code instant} is a readable UTC time no later than now, with the clock skew allowed. */
    private static boolean notInFuture(String instant) {
        try {
            return instant != null
                    && !Instant.parse(instant).isAfter(Instant.now().plusSeconds(clockSkewSeconds()));
        } catch (java.time.format.DateTimeParseException unreadable) {
            return false;
        }
    }

    /**
     * How deep elements may nest in a credential. A SAML Response nests about ten deep; this is the limit
     * JDK 25 applies by default. JDK 21's default is none, and on it fifty thousand nested elements in a
     * signed assertion's {@code <Advice>} — 350 KB — overflowed the stack inside the signature check, before
     * the signature was even looked at (R-09). Set here so it holds whatever the JDK or the
     * {@code jdk.xml.maxElementDepth} system property says.
     */
    static final int MAX_ELEMENT_DEPTH = 100;

    /**
     * Parses the XML with DTDs disallowed and external entities disabled (XXE-safe), and elements nested
     * no deeper than {@link #MAX_ELEMENT_DEPTH}.
     */
    private static Document parseSecurely(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        dbf.setAttribute("http://www.oracle.com/xml/jaxp/properties/maxElementDepth",
                String.valueOf(MAX_ELEMENT_DEPTH));
        DocumentBuilder builder = dbf.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xml));
    }

    private static byte[] toXmlBytes(String credential) {
        String trimmed = credential == null ? "" : credential.trim();
        if (trimmed.startsWith("<")) {
            return trimmed.getBytes(StandardCharsets.UTF_8);
        }
        return Base64.getMimeDecoder().decode(trimmed);
    }

    // ---- precise namespace-aware DOM navigation (direct children only) ----

    private static Element firstChild(Element parent, String ns, String local) {
        if (parent == null) {
            return null;
        }
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE && ns.equals(n.getNamespaceURI()) && local.equals(n.getLocalName())) {
                return (Element) n;
            }
        }
        return null;
    }

    private static List<Element> children(Element parent, String ns, String local) {
        List<Element> out = new ArrayList<>();
        if (parent != null) {
            for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
                if (n.getNodeType() == Node.ELEMENT_NODE && ns.equals(n.getNamespaceURI()) && local.equals(n.getLocalName())) {
                    out.add((Element) n);
                }
            }
        }
        return out;
    }

    private static Element onlyChild(Element parent, String local, SamlVerificationResult result) {
        List<Element> matches = children(parent, NS, local);
        if (matches.size() != 1) {
            result.error("Expected exactly one <" + local + "> in the verified assertion, found " + matches.size());
            return null;
        }
        return matches.get(0);
    }

    /** Each {@code <AudienceRestriction>}'s audiences, one list per restriction. */
    private static List<List<String>> audienceRestrictions(Element conditions) {
        List<List<String>> out = new ArrayList<>();
        for (Element restriction : children(conditions, NS, "AudienceRestriction")) {
            List<String> audiences = new ArrayList<>();
            for (Element audience : children(restriction, NS, "Audience")) {
                audiences.add(audience.getTextContent().trim());
            }
            out.add(audiences);
        }
        return out;
    }

    private static final String XSI_NS = "http://www.w3.org/2001/XMLSchema-instance";

    /**
     * Why {@code conditions} cannot be evaluated, or {@code null} if every condition in it is one this
     * verifier understands (SAML Core §2.5.1): {@code <AudienceRestriction>}s of non-blank
     * {@code <Audience>}s, at most one {@code <OneTimeUse>} (§2.5.1.5) and at most one
     * {@code <ProxyRestriction>} (§2.5.1.6) — a restriction on what a relying party may go on to assert,
     * which does not affect the assertion's validity here. A {@code <Condition>} is an extension point,
     * and an extension this verifier does not implement is the "not understood" §2.5.1.1 means.
     */
    private static String conditionsProblem(Element conditions) {
        if (conditions == null) {
            return null;
        }
        int oneTimeUse = 0;
        int proxyRestriction = 0;
        for (Node n = conditions.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            Element condition = (Element) n;
            String name = condition.getLocalName();
            if (!NS.equals(condition.getNamespaceURI())) {
                return "<" + name + "> is not a SAML condition";
            }
            switch (name) {
                case "AudienceRestriction" -> {
                    List<Element> audiences = children(condition, NS, "Audience");
                    if (audiences.isEmpty() || audiences.size() != elementChildren(condition)) {
                        return "an <AudienceRestriction> holds something other than <Audience> elements, or none";
                    }
                    for (Element audience : audiences) {
                        if (audience.getTextContent().isBlank()) {
                            return "an <Audience> is empty";
                        }
                    }
                }
                case "OneTimeUse" -> {
                    if (++oneTimeUse > 1) {
                        return "more than one <OneTimeUse>";
                    }
                }
                case "ProxyRestriction" -> {
                    if (++proxyRestriction > 1) {
                        return "more than one <ProxyRestriction>";
                    }
                }
                case "Condition" -> {
                    String type = condition.getAttributeNS(XSI_NS, "type");
                    return "a <Condition> of type '" + type + "' is not one this verifier understands";
                }
                default -> {
                    return "<" + name + "> is not a SAML condition";
                }
            }
        }
        return null;
    }

    private static int elementChildren(Element parent) {
        int count = 0;
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE) {
                count++;
            }
        }
        return count;
    }

    /** True iff {@code value} is an absolute URI: it parses, and it has a scheme. */
    static boolean isAbsoluteUri(String value) {
        try {
            java.net.URI uri = new java.net.URI(value);
            return uri.isAbsolute() && !uri.getSchemeSpecificPart().isEmpty();
        } catch (java.net.URISyntaxException notAUri) {
            return false;
        }
    }

    private static String attr(Element e, String name) {
        return e != null && e.hasAttribute(name) ? e.getAttribute(name) : null;
    }

    private static boolean withinValidity(String notBefore, String notOnOrAfter) {
        Instant now = Instant.now();
        try {
            if (notBefore != null && !notBefore.isBlank()
                    && now.isBefore(Instant.parse(notBefore).minusSeconds(clockSkewSeconds()))) {
                return false;
            }
            if (notOnOrAfter != null && !notOnOrAfter.isBlank()
                    && !now.isBefore(Instant.parse(notOnOrAfter).plusSeconds(clockSkewSeconds()))) {
                return false;
            }
            return true;
        } catch (Exception e) {
            return false; // unparseable timestamps -> reject
        }
    }
}
