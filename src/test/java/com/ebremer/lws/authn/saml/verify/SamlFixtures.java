/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.saml.verify;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Builds and signs the SAML Responses the verifier tests feed it: a template an IdP would send, the
 * XML-DSig signing an IdP does, and self-signed IdP certificates with chosen validity windows.
 */
final class SamlFixtures {

    private SamlFixtures() {
    }

    static final String NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    static final String PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
    static final String AUDIENCE = "https://app.example/SAML";
    /** LWS core §4.1: a subject "MUST be a URI" (R-20). These used to be bare names. */
    static final String ALICE = "https://id.example/alice";
    static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

    static Element assertionOf(Document doc) {
        return (Element) doc.getElementsByTagNameNS(NS, "Assertion").item(0);
    }

    /** The transforms an IdP uses: enveloped signature, then exclusive canonicalization. */
    static List<Transform> standardTransforms() throws Exception {
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        return List.of(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null));
    }

    /**
     * Signs {@code target} with an enveloped signature: one reference to its ID with the given digest and
     * transforms, plus {@code extraWholeDocumentReferences} references to the whole document.
     */
    static void sign(Element target, PrivateKey key, String method, String digest,
                     List<Transform> transforms, int extraWholeDocumentReferences) throws Exception {
        target.setIdAttribute("ID", true);
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        List<Reference> references = new ArrayList<>();
        references.add(fac.newReference("#" + target.getAttribute("ID"), fac.newDigestMethod(digest, null),
                transforms, null, null));
        for (int i = 0; i < extraWholeDocumentReferences; i++) {
            references.add(fac.newReference("", fac.newDigestMethod(digest, null), standardTransforms(), null, null));
        }
        SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(method, null), references);
        fac.newXMLSignature(si, null).sign(new DOMSignContext(key, target));
    }

    /**
     * Places an enveloped RSA-SHA256 signature in {@code parent} whose single reference is {@code uri} —
     * a well-formed signature that may cover something other than the element it sits in. Every element
     * with an {@code ID} is registered, so a same-document reference to any of them resolves.
     */
    static void signReferencing(Document doc, Element parent, String uri, PrivateKey key) throws Exception {
        org.w3c.dom.NodeList all = doc.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Element element = (Element) all.item(i);
            if (element.hasAttribute("ID")) {
                element.setIdAttribute("ID", true);
            }
        }
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference reference = fac.newReference(uri, fac.newDigestMethod(DigestMethod.SHA256, null),
                standardTransforms(), null, null);
        SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        fac.newXMLSignature(si, null).sign(new DOMSignContext(key, parent));
    }

    /** Rewrites the SubjectConfirmationData NotOnOrAfter in a response template. */
    static String withSubjectConfirmationExpiry(String xml, String notOnOrAfter) {
        int start = xml.indexOf("<saml:SubjectConfirmationData");
        int end = xml.indexOf("/>", start);
        String replacement = "<saml:SubjectConfirmationData Recipient=" + '"' + AUDIENCE + '"'
                + " NotOnOrAfter=" + '"' + notOnOrAfter + '"';
        return xml.substring(0, start) + replacement + xml.substring(end);
    }

    static String responseTemplate(String nameId) {
        String now = iso(0), nb = iso(-60), exp = iso(3600);
        return "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"" + NS
                + "\" ID=\"r1\" Version=\"2.0\" IssueInstant=\"" + now + "\">"
                + "<saml:Issuer>https://idp.example</saml:Issuer>"
                + status(STATUS_SUCCESS)
                + "<saml:Assertion ID=\"a1\" Version=\"2.0\" IssueInstant=\"" + now + "\">"
                + "<saml:Issuer>https://idp.example</saml:Issuer>"
                + "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">"
                + nameId + "</saml:NameID>"
                + "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                + "<saml:SubjectConfirmationData Recipient=\"" + AUDIENCE + "\" NotOnOrAfter=\"" + exp + "\"/>"
                + "</saml:SubjectConfirmation></saml:Subject>"
                + "<saml:Conditions NotBefore=\"" + nb + "\" NotOnOrAfter=\"" + exp + "\">"
                + "<saml:AudienceRestriction><saml:Audience>" + AUDIENCE + "</saml:Audience></saml:AudienceRestriction>"
                + "</saml:Conditions>"
                + "<saml:AuthnStatement AuthnInstant=\"" + now + "\"><saml:AuthnContext>"
                + "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml:AuthnContextClassRef>"
                + "</saml:AuthnContext></saml:AuthnStatement>"
                + "</saml:Assertion></samlp:Response>";
    }

    /** Like {@link #responseTemplate} but the assertion's {@code <Conditions>} has no NotOnOrAfter. */
    static String responseTemplateNoExpiry(String nameId) {
        String now = iso(0), nb = iso(-60), exp = iso(3600);
        return "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"" + NS
                + "\" ID=\"r1\" Version=\"2.0\" IssueInstant=\"" + now + "\">"
                + "<saml:Issuer>https://idp.example</saml:Issuer>"
                + status(STATUS_SUCCESS)
                + "<saml:Assertion ID=\"a1\" Version=\"2.0\" IssueInstant=\"" + now + "\">"
                + "<saml:Issuer>https://idp.example</saml:Issuer>"
                + "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">"
                + nameId + "</saml:NameID>"
                + "<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">"
                + "<saml:SubjectConfirmationData Recipient=\"" + AUDIENCE + "\" NotOnOrAfter=\"" + exp + "\"/>"
                + "</saml:SubjectConfirmation></saml:Subject>"
                + "<saml:Conditions NotBefore=\"" + nb + "\">" // no NotOnOrAfter -> unbounded
                + "<saml:AudienceRestriction><saml:Audience>" + AUDIENCE + "</saml:Audience></saml:AudienceRestriction>"
                + "</saml:Conditions>"
                + "</saml:Assertion></samlp:Response>";
    }

    static void signAssertion(Document doc, PrivateKey key) throws Exception {
        Element assertion = (Element) doc.getElementsByTagNameNS(NS, "Assertion").item(0);
        assertion.setIdAttribute("ID", true);
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference ref = fac.newReference("#" + assertion.getAttribute("ID"),
                fac.newDigestMethod(DigestMethod.SHA256, null),
                List.of(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                        fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null)),
                null, null);
        SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(ref));
        fac.newXMLSignature(si, null).sign(new DOMSignContext(key, assertion));
    }

    static void injectForgedAssertion(Document doc, String nameId) throws Exception {
        Document forged = parse("<saml:Assertion xmlns:saml=\"" + NS + "\" ID=\"a2\" Version=\"2.0\" IssueInstant=\""
                + iso(0) + "\"><saml:Issuer>https://idp.example</saml:Issuer>"
                + "<saml:Subject><saml:NameID>" + nameId + "</saml:NameID></saml:Subject>"
                + "<saml:Conditions NotBefore=\"" + iso(-60) + "\" NotOnOrAfter=\"" + iso(3600) + "\">"
                + "<saml:AudienceRestriction><saml:Audience>" + AUDIENCE + "</saml:Audience></saml:AudienceRestriction>"
                + "</saml:Conditions></saml:Assertion>");
        Element node = (Element) doc.importNode(forged.getDocumentElement(), true);
        Element response = doc.getDocumentElement();
        response.insertBefore(node, response.getFirstChild());
    }

    static String status(String code) {
        return "<samlp:Status><samlp:StatusCode Value=\"" + code + "\"/></samlp:Status>";
    }

    static String iso(long offsetSec) {
        return Instant.now().plusSeconds(offsetSec).truncatedTo(ChronoUnit.SECONDS).toString();
    }

    static Document parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    static String serialize(Document doc) throws Exception {
        Transformer t = TransformerFactory.newInstance().newTransformer();
        StringWriter sw = new StringWriter();
        t.transform(new DOMSource(doc), new StreamResult(sw));
        return sw.toString();
    }

    static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    static KeyPair ecP256() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    static X509Certificate selfSigned(KeyPair kp) throws Exception {
        return certificate(kp, -1000L, 86_400_000L);
    }

    /** A self-signed certificate whose validity window is offset from now by the given milliseconds. */
    static X509Certificate certificate(KeyPair kp, long notBeforeOffset, long notAfterOffset)
            throws Exception {
        long now = System.currentTimeMillis();
        X500Name dn = new X500Name("CN=test-idp");
        ContentSigner signer = new JcaContentSignerBuilder(
                "EC".equals(kp.getPublic().getAlgorithm()) ? "SHA256withECDSA" : "SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(dn, BigInteger.valueOf(now),
                        new Date(now + notBeforeOffset), new Date(now + notAfterOffset),
                        dn, kp.getPublic()).build(signer));
    }
}
