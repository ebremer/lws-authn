package com.ebremer.lws.authn.saml.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SamlVerifierTest {

    private static final String NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String AUDIENCE = "https://app.example/SAML";

    private KeyPair idpKeyPair;
    private X509Certificate idpCert;

    @BeforeAll
    void keys() throws Exception {
        idpKeyPair = rsa();
        idpCert = selfSigned(idpKeyPair);
    }

    @Test
    void validSignedAssertionVerifies() throws Exception {
        String xml = signedResponse("alice");
        SamlVerificationResult r = new SamlCredentialVerifier().verify(xml, idpCert, AUDIENCE);
        assertTrue(r.isValid(), () -> "expected valid, errors: " + r.getErrors());
        assertEquals("alice", r.getSubject());
    }

    @Test
    void tamperedSubjectRejected() throws Exception {
        String xml = signedResponse("alice").replace(">alice<", ">attacker<");
        SamlVerificationResult r = new SamlCredentialVerifier().verify(xml, idpCert, AUDIENCE);
        assertFalse(r.isValid(), "a tampered NameID must not validate");
    }

    @Test
    void wrongCertificateRejected() throws Exception {
        String xml = signedResponse("alice");
        SamlVerificationResult r = new SamlCredentialVerifier().verify(xml, selfSigned(rsa()), AUDIENCE);
        assertFalse(r.isValid(), "signature must not validate against a different certificate");
    }

    /**
     * Signature wrapping: sign an assertion for "alice", then inject a forged, unsigned assertion for
     * "attacker" as the first child of the Response. A naive verifier (first NameID in the document)
     * would read "attacker"; the hardened verifier reads only the cryptographically-covered assertion.
     */
    @Test
    void signatureWrappingDefeated() throws Exception {
        Document doc = parse(responseTemplate("alice"));
        signAssertion(doc, idpKeyPair.getPrivate());
        injectForgedAssertion(doc, "attacker");
        SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);

        assertNotEquals("attacker", r.getSubject(), "XML signature wrapping succeeded — read the forged identity!");
        assertEquals("alice", r.getSubject(), "must read the signed identity");
        assertTrue(r.isValid(), () -> "the genuine credential should still validate, errors: " + r.getErrors());
    }

    /** XXE: a credential containing a DOCTYPE / external entity must be rejected at parse time. */
    @Test
    void xxeDoctypeRejected() {
        String xxe = "<!DOCTYPE root [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
                + "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"" + NS
                + "\" ID=\"r1\"><saml:Issuer>&x;</saml:Issuer></samlp:Response>";
        SamlVerificationResult r = new SamlCredentialVerifier().verify(xxe, idpCert, AUDIENCE);
        assertFalse(r.isValid(), "a document with a DOCTYPE must be rejected (XXE)");
    }

    /**
     * Replay hardening: an otherwise-valid, correctly-signed assertion whose {@code <Conditions>}
     * carries no {@code NotOnOrAfter} has no upper time bound and must be rejected.
     */
    @Test
    void assertionWithoutExpiryRejected() throws Exception {
        Document doc = parse(responseTemplateNoExpiry("alice"));
        signAssertion(doc, idpKeyPair.getPrivate());
        SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);
        assertFalse(r.isValid(), "an assertion with no Conditions/@NotOnOrAfter must be rejected");
        assertEquals(Boolean.FALSE, r.getChecks().get("withinValidityWindow"));
    }

    // --------------------------------------------------------------------------- SAML construction

    private String signedResponse(String nameId) throws Exception {
        Document doc = parse(responseTemplate(nameId));
        signAssertion(doc, idpKeyPair.getPrivate());
        return serialize(doc);
    }

    private static String responseTemplate(String nameId) {
        String now = iso(0), nb = iso(-60), exp = iso(3600);
        return "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"" + NS
                + "\" ID=\"r1\" Version=\"2.0\" IssueInstant=\"" + now + "\">"
                + "<saml:Issuer>https://idp.example</saml:Issuer>"
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
    private static String responseTemplateNoExpiry(String nameId) {
        String now = iso(0), nb = iso(-60);
        return "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"" + NS
                + "\" ID=\"r1\" Version=\"2.0\" IssueInstant=\"" + now + "\">"
                + "<saml:Issuer>https://idp.example</saml:Issuer>"
                + "<saml:Assertion ID=\"a1\" Version=\"2.0\" IssueInstant=\"" + now + "\">"
                + "<saml:Issuer>https://idp.example</saml:Issuer>"
                + "<saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">"
                + nameId + "</saml:NameID></saml:Subject>"
                + "<saml:Conditions NotBefore=\"" + nb + "\">" // no NotOnOrAfter -> unbounded
                + "<saml:AudienceRestriction><saml:Audience>" + AUDIENCE + "</saml:Audience></saml:AudienceRestriction>"
                + "</saml:Conditions>"
                + "</saml:Assertion></samlp:Response>";
    }

    private static void signAssertion(Document doc, PrivateKey key) throws Exception {
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

    private static void injectForgedAssertion(Document doc, String nameId) throws Exception {
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

    // ---------------------------------------------------------------------------------- utilities

    private static String iso(long offsetSec) {
        return Instant.now().plusSeconds(offsetSec).truncatedTo(ChronoUnit.SECONDS).toString();
    }

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        return dbf.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    private static String serialize(Document doc) throws Exception {
        Transformer t = TransformerFactory.newInstance().newTransformer();
        StringWriter sw = new StringWriter();
        t.transform(new DOMSource(doc), new StreamResult(sw));
        return sw.toString();
    }

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    private static X509Certificate selfSigned(KeyPair kp) throws Exception {
        long now = System.currentTimeMillis();
        X500Name dn = new X500Name("CN=test-idp");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(dn, BigInteger.valueOf(now),
                        new Date(now - 1000), new Date(now + 86_400_000L), dn, kp.getPublic()).build(signer));
    }
}
