/*
 * Copyright Erich Bremer.
 *
 * Validates a signed SAML 2.0 assertion as an LWS authentication credential, per
 * https://w3c.github.io/lws-protocol/lws10-authn-saml/
 *
 * Hardening:
 *   - XXE: the XML is parsed with a locally-configured, DTD-disallowing parser (not the caller's).
 *   - XML Signature Wrapping (XSW): the signature is validated AND the signature's Reference must
 *     cover the signed element by its own ID; claims are then read ONLY from within the
 *     cryptographically-covered assertion (a single assertion), by precise direct-child navigation —
 *     never a document-wide getElementsByTagName that an injected element could win.
 *
 * Trust is out of band (the verifier is given the IdP certificate). Signature validation uses
 * Keycloak's SAML processing library.
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
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.keycloak.saml.processing.core.saml.v2.util.AssertionUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.ebremer.lws.authn.saml.SamlConstants;

/**
 * @author Erich Bremer
 */
public class SamlCredentialVerifier {

    private static final long CLOCK_SKEW_SECONDS = 60;
    private static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String NS = SamlConstants.SAML_ASSERTION_NS;

    /**
     * @param credential       the SAML 2.0 Response, as XML or base64-encoded XML
     * @param idpCertificate   the trusted IdP signing certificate (established out of band)
     * @param expectedAudience optional audience the assertion must be restricted to
     */
    public SamlVerificationResult verify(String credential, X509Certificate idpCertificate, String expectedAudience) {
        SamlVerificationResult result = new SamlVerificationResult();
        try {
            Document doc = parseSecurely(toXmlBytes(credential));

            // --- signature ---
            Element signed = findSignedElement(doc);
            result.check("signaturePresent", signed != null);
            if (signed == null) {
                result.error("Credential is not signed (no enveloped XML signature on the Response or Assertion)");
                return result.fail();
            }
            boolean signatureValid = AssertionUtil.isSignatureValid(signed, idpCertificate.getPublicKey());
            result.check("signatureValid", signatureValid);
            if (!signatureValid) {
                result.error("XML signature is not valid for the supplied IdP certificate");
                return result.fail();
            }
            // anti-wrapping: the signature must reference the signed element by its own ID
            boolean coversSignedElement = signatureCoversOwnId(signed);
            result.check("signatureCoversSignedElement", coversSignedElement);
            if (!coversSignedElement) {
                result.error("Signature does not cover the signed element by its ID (possible signature wrapping)");
                return result.fail();
            }

            // --- the cryptographically-covered assertion; claims are read ONLY from here ---
            Element assertion = verifiedAssertion(signed, result);
            if (assertion == null) {
                return result.fail();
            }

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
            if (subjectValue.isEmpty()) {
                result.error("Assertion <NameID> subject is empty");
                return result.fail();
            }

            Element issuer = firstChild(assertion, NS, "Issuer");
            result.setIssuer(issuer == null ? null : issuer.getTextContent().trim());

            Element scd = descend(subject, "SubjectConfirmation", "SubjectConfirmationData");
            if (scd != null && scd.hasAttribute("Recipient")) {
                result.setRecipient(scd.getAttribute("Recipient"));
            }

            // --- validity window ---
            Element conditions = firstChild(assertion, NS, "Conditions");
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
            List<String> audiences = audiences(conditions);
            result.setAudiences(audiences);
            if (expectedAudience != null && !expectedAudience.isBlank()) {
                boolean matched = audiences.contains(expectedAudience);
                result.check("audienceMatched", matched);
                if (!matched) {
                    result.error("Expected audience <" + expectedAudience + "> is not in the assertion's AudienceRestriction");
                    return result.fail();
                }
            } else {
                boolean present = !audiences.isEmpty();
                result.check("audiencePresent", present);
                if (!present) {
                    result.error("Assertion has no <AudienceRestriction>");
                    return result.fail();
                }
            }

            result.setValid(result.getErrors().isEmpty());
        } catch (Exception e) {
            result.error(e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage()));
            return result.fail();
        }
        return result;
    }

    /** The single assertion inside a signed Response, or the signed Assertion itself. */
    private static Element verifiedAssertion(Element signed, SamlVerificationResult result) {
        String localName = signed.getLocalName();
        if ("Assertion".equals(localName) && NS.equals(signed.getNamespaceURI())) {
            return signed;
        }
        if ("Response".equals(localName)) {
            List<Element> assertions = children(signed, NS, "Assertion");
            if (assertions.size() != 1) {
                result.check("singleAssertion", false);
                result.error("A signed Response must contain exactly one Assertion, found " + assertions.size());
                return null;
            }
            return assertions.get(0);
        }
        result.error("Signed element is neither a SAML Response nor a SAML Assertion");
        return null;
    }

    /** True iff the {@code ds:Signature} child of {@code signed} references {@code signed}'s own ID. */
    private static boolean signatureCoversOwnId(Element signed) {
        String id = signed.getAttribute("ID");
        if (id == null || id.isEmpty()) {
            return false;
        }
        Element signature = firstChild(signed, XMLDSIG_NS, "Signature");
        Element signedInfo = signature == null ? null : firstChild(signature, XMLDSIG_NS, "SignedInfo");
        if (signedInfo == null) {
            return false;
        }
        for (Element reference : children(signedInfo, XMLDSIG_NS, "Reference")) {
            if (("#" + id).equals(reference.getAttribute("URI"))) {
                return true;
            }
        }
        return false;
    }

    /** The Response (if it carries a signature) or the first directly-signed Assertion. */
    private static Element findSignedElement(Document doc) {
        Element root = doc.getDocumentElement();
        if (root != null && firstChild(root, XMLDSIG_NS, "Signature") != null) {
            return root;
        }
        NodeList assertions = doc.getElementsByTagNameNS(NS, "Assertion");
        for (int i = 0; i < assertions.getLength(); i++) {
            Element a = (Element) assertions.item(i);
            if (firstChild(a, XMLDSIG_NS, "Signature") != null) {
                return a;
            }
        }
        return null;
    }

    /** Parses the XML with DTDs disallowed and external entities disabled (XXE-safe). */
    private static Document parseSecurely(byte[] xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
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

    private static Element descend(Element parent, String childLocal, String grandchildLocal) {
        Element child = firstChild(parent, NS, childLocal);
        return child == null ? null : firstChild(child, NS, grandchildLocal);
    }

    private static Element onlyChild(Element parent, String local, SamlVerificationResult result) {
        List<Element> matches = children(parent, NS, local);
        if (matches.size() != 1) {
            result.error("Expected exactly one <" + local + "> in the verified assertion, found " + matches.size());
            return null;
        }
        return matches.get(0);
    }

    private static List<String> audiences(Element conditions) {
        List<String> out = new ArrayList<>();
        for (Element restriction : children(conditions, NS, "AudienceRestriction")) {
            for (Element audience : children(restriction, NS, "Audience")) {
                out.add(audience.getTextContent().trim());
            }
        }
        return out;
    }

    private static String attr(Element e, String name) {
        return e != null && e.hasAttribute(name) ? e.getAttribute(name) : null;
    }

    private static boolean withinValidity(String notBefore, String notOnOrAfter) {
        Instant now = Instant.now();
        try {
            if (notBefore != null && !notBefore.isBlank()
                    && now.isBefore(Instant.parse(notBefore).minusSeconds(CLOCK_SKEW_SECONDS))) {
                return false;
            }
            if (notOnOrAfter != null && !notOnOrAfter.isBlank()
                    && !now.isBefore(Instant.parse(notOnOrAfter).plusSeconds(CLOCK_SKEW_SECONDS))) {
                return false;
            }
            return true;
        } catch (Exception e) {
            return false; // unparseable timestamps -> reject
        }
    }
}
