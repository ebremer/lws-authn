/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.saml.verify;

import static com.ebremer.lws.authn.saml.verify.SamlFixtures.ALICE;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.AUDIENCE;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.NS;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.STATUS_SUCCESS;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.assertionOf;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.certificate;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.ecP256;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.injectForgedAssertion;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.iso;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.parse;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.responseTemplate;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.responseTemplateNoExpiry;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.rsa;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.selfSigned;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.serialize;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.sign;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.signAssertion;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.standardTransforms;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.status;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.withSubjectConfirmationExpiry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.crypto.dsig.spec.XPathFilterParameterSpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.keycloak.models.IdentityProviderModel;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SamlVerifierTest {

    private static final String ATTACKER = "https://id.example/attacker";
    private static final String Q = "\"";
    private static final String STATUS_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder";

    private KeyPair idpKeyPair;
    private X509Certificate idpCert;

    @BeforeAll
    void keys() throws Exception {
        idpKeyPair = rsa();
        idpCert = selfSigned(idpKeyPair);
    }

    @Test
    void validSignedAssertionVerifies() throws Exception {
        String xml = signedResponse(ALICE);
        SamlVerificationResult r = new SamlCredentialVerifier().verify(xml, idpCert, AUDIENCE);
        assertTrue(r.isValid(), () -> "expected valid, errors: " + r.getErrors());
        assertEquals(ALICE, r.getSubject());
    }

    @Test
    void tamperedSubjectRejected() throws Exception {
        String xml = signedResponse(ALICE).replace(">" + ALICE + "<", ">" + ATTACKER + "<");
        SamlVerificationResult r = new SamlCredentialVerifier().verify(xml, idpCert, AUDIENCE);
        assertFalse(r.isValid(), "a tampered NameID must not validate");
    }

    @Test
    void wrongCertificateRejected() throws Exception {
        String xml = signedResponse(ALICE);
        SamlVerificationResult r = new SamlCredentialVerifier().verify(xml, selfSigned(rsa()), AUDIENCE);
        assertFalse(r.isValid(), "signature must not validate against a different certificate");
    }

    /**
     * Signature wrapping: sign an assertion for "alice", then inject a forged, unsigned assertion for
     * "attacker" as the first child of the Response. A naive verifier (first NameID in the document)
     * would read "attacker". This one used to find the signed assertion and verify it; since R-22 a
     * Response must hold exactly one assertion, as a signed one always had to, so it is refused outright.
     */
    @Test
    void signatureWrappingDefeated() throws Exception {
        Document doc = parse(responseTemplate(ALICE));
        signAssertion(doc, idpKeyPair.getPrivate());
        injectForgedAssertion(doc, ATTACKER);
        SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);

        assertNotEquals(ATTACKER, r.getSubject(), "XML signature wrapping succeeded — read the forged identity!");
        assertFalse(r.isValid(), "a Response with two assertions has no single credential");
        assertEquals(Boolean.FALSE, r.getChecks().get("singleAssertion"));
    }

    /**
     * R-31. A forged assertion tucked into {@code <samlp:Extensions>} of an unsigned Response, ahead of the
     * signed one, was never read here — the verifier found the signed one by position and answered
     * {@code valid: true} for it. But a consumer that re-parses the credential and takes the first
     * {@code Assertion} element would read the forgery, so the document is refused. So is one hiding the
     * forgery under a look-alike namespace, for a consumer matching by local name.
     */
    @Test
    void anAssertionOutsideItsPlaceIsRefused() throws Exception {
        for (String namespace : new String[]{NS, "urn:example:not-saml"}) {
            Document doc = parse(responseTemplate(ALICE));
            signAssertion(doc, idpKeyPair.getPrivate());
            injectForgedAssertion(doc, ATTACKER);
            Element response = doc.getDocumentElement();
            Element forged = (Element) response.getFirstChild();
            if (!NS.equals(namespace)) {
                forged = (Element) doc.renameNode(forged, namespace, "x:Assertion");
            }
            Element extensions = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:protocol", "samlp:Extensions");
            extensions.appendChild(forged); // the forged assertion, moved inside
            response.insertBefore(extensions, response.getFirstChild());

            SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);

            assertFalse(r.isValid(), namespace);
            assertEquals(Boolean.FALSE, r.getChecks().get("singleAssertion"), namespace);
            assertNotEquals(ATTACKER, r.getSubject());
        }
    }

    /**
     * R-32. Base64 as the POST binding sends it — wrapped at 76 characters — is read; a character outside
     * the alphabet is refused. The MIME decoder this used skipped such characters, so what was verified
     * was not quite what was sent.
     */
    @Test
    void base64IsReadStrictly() throws Exception {
        String wrapped = java.util.Base64.getMimeEncoder().encodeToString(
                signedResponse(ALICE).getBytes(StandardCharsets.UTF_8));
        assertTrue(wrapped.contains("\r\n"));
        SamlVerificationResult r = new SamlCredentialVerifier().verify(wrapped, idpCert, AUDIENCE);
        assertTrue(r.isValid(), () -> r.getErrors().toString());

        String stray = wrapped.substring(0, 40) + "*" + wrapped.substring(40);
        assertFalse(new SamlCredentialVerifier().verify(stray, idpCert, AUDIENCE).isValid());
    }

    /** An encrypted identifier is not supported either, and says so. */
    @Test
    void anEncryptedIdIsRefused() throws Exception {
        String xml = responseTemplate(ALICE).replace("<saml:Subject>",
                "<saml:Subject><saml:EncryptedID/>");
        Document doc = parse(xml);
        signAssertion(doc, idpKeyPair.getPrivate());
        SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);
        assertFalse(r.isValid());
        assertTrue(r.getErrors().toString().contains("Encrypted identifiers are not supported"), r.getErrors().toString());
    }

    /** An encrypted assertion is not supported, and is refused rather than passed over. */
    @Test
    void anEncryptedAssertionIsRefused() throws Exception {
        Document doc = parse(responseTemplate(ALICE));
        signAssertion(doc, idpKeyPair.getPrivate());
        Element response = doc.getDocumentElement();
        response.insertBefore(doc.createElementNS(NS, "saml:EncryptedAssertion"), response.getLastChild());

        SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);

        assertFalse(r.isValid());
        assertTrue(r.getErrors().toString().contains("Encrypted assertions are not supported"), r.getErrors().toString());
    }

    /**
     * R-09. Fifty thousand nested elements in a signed assertion overflowed the stack inside the
     * signature check when the XML parser set no depth limit — JDK 21's default — and the
     * {@link StackOverflowError} escaped every handler as a {@code 500}. The verifier now sets its own
     * limit rather than relying on the JDK's.
     */
    @Test
    void deeplyNestedElementsAreRefusedNotOverflowed() throws Exception {
        String previous = System.getProperty("jdk.xml.maxElementDepth");
        System.setProperty("jdk.xml.maxElementDepth", "0"); // no limit, as on JDK 21
        try {
            StringBuilder advice = new StringBuilder("<saml:Advice>");
            for (int i = 0; i < 50_000; i++) {
                advice.append("<x>");
            }
            for (int i = 0; i < 50_000; i++) {
                advice.append("</x>");
            }
            advice.append("</saml:Advice>");
            String xml = signedResponse(ALICE).replaceFirst(
                    "(<saml:Assertion[^>]*><saml:Issuer>[^<]*</saml:Issuer>)", "$1" + advice);
            assertTrue(xml.contains("<saml:Advice>"));
            SamlVerificationResult r = new SamlCredentialVerifier().verify(xml, idpCert, AUDIENCE);
            assertFalse(r.isValid());
        } finally {
            if (previous == null) {
                System.clearProperty("jdk.xml.maxElementDepth");
            } else {
                System.setProperty("jdk.xml.maxElementDepth", previous);
            }
        }
    }

    private String signed(String xml) throws Exception {
        Document doc = parse(xml);
        signAssertion(doc, idpKeyPair.getPrivate());
        return serialize(doc);
    }

    /**
     * R-20. LWS core §4.1: the subject "MUST be a URI". A bare name, an email address or an opaque
     * handle names someone only to this IdP.
     */
    @Test
    void aSubjectThatIsNotAUriIsRejected() throws Exception {
        for (String nameId : new String[]{"alice", "alice@example.org", "3f2a9c1e-77b0-4f1a-9e1d-2c5b8e0a6d41",
                "/relative/path", "urn:"}) {
            SamlVerificationResult r = new SamlCredentialVerifier().verify(signed(responseTemplate(nameId)),
                    idpCert, AUDIENCE);
            assertFalse(r.isValid(), nameId);
            assertEquals(Boolean.FALSE, r.getChecks().get("subjectIsUri"), nameId);
        }
        for (String nameId : new String[]{"urn:uuid:3f2a9c1e-77b0-4f1a-9e1d-2c5b8e0a6d41",
                "did:key:z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"}) {
            SamlVerificationResult r = new SamlCredentialVerifier().verify(signed(responseTemplate(nameId)),
                    idpCert, AUDIENCE);
            assertTrue(r.isValid(), () -> nameId + ": " + r.getErrors());
        }
    }

    /**
     * R-20. LWS core §4.1: the issuer "MUST be a URI"; SAML Profiles §4.1.4.2: its Format "MUST be
     * omitted or have a value of urn:oasis:names:tc:SAML:2.0:nameid-format:entity".
     */
    @Test
    void anIssuerThatIsNotAnEntityUriIsRejected() throws Exception {
        String issuer = "<saml:Issuer>https://idp.example</saml:Issuer>";
        for (String replacement : new String[]{"<saml:Issuer>idp</saml:Issuer>",
                "<saml:Issuer Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">https://idp.example</saml:Issuer>"}) {
            SamlVerificationResult r = new SamlCredentialVerifier().verify(
                    signed(responseTemplate(ALICE).replace(issuer, replacement)), idpCert, AUDIENCE);
            assertFalse(r.isValid(), replacement);
            assertEquals(Boolean.FALSE, r.getChecks().get("issuerWellFormed"), replacement);
        }
        SamlVerificationResult entity = new SamlCredentialVerifier().verify(signed(responseTemplate(ALICE).replace(issuer,
                "<saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://idp.example</saml:Issuer>")),
                idpCert, AUDIENCE);
        assertTrue(entity.isValid(), () -> String.valueOf(entity.getErrors()));
    }

    /** R-20. The NameID's Format is reported, so a caller can see what kind of identifier it got. */
    @Test
    void reportsTheNameIdFormat() throws Exception {
        SamlVerificationResult r = new SamlCredentialVerifier().verify(signedResponse(ALICE), idpCert, AUDIENCE);
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", r.getSubjectFormat());
    }

    // ----------------------------------------------------------------- <Conditions> (R-21)

    private static final String RESTRICTION = "<saml:AudienceRestriction><saml:Audience>" + AUDIENCE
            + "</saml:Audience></saml:AudienceRestriction>";

    /** The response template with the {@code <AudienceRestriction>} replaced by {@code conditions}. */
    private String withConditions(String conditions) throws Exception {
        String xml = responseTemplate(ALICE);
        assertTrue(xml.contains(RESTRICTION));
        return signed(xml.replace(RESTRICTION, conditions));
    }

    /**
     * SAML Core §2.5.1.4: several {@code <AudienceRestriction>}s "each MUST be evaluated independently"
     * and form a conjunction. They used to be pooled, so [app] AND [elsewhere] passed for app.
     */
    @Test
    void everyAudienceRestrictionMustNameTheAudience() throws Exception {
        String elsewhere = "<saml:AudienceRestriction><saml:Audience>https://only-this-one.example</saml:Audience>"
                + "</saml:AudienceRestriction>";
        SamlVerificationResult r = new SamlCredentialVerifier().verify(withConditions(RESTRICTION + elsewhere),
                idpCert, AUDIENCE);
        assertFalse(r.isValid());
        assertEquals(Boolean.FALSE, r.getChecks().get("audienceMatched"));

        String alsoApp = "<saml:AudienceRestriction><saml:Audience>https://only-this-one.example</saml:Audience>"
                + "<saml:Audience>" + AUDIENCE + "</saml:Audience></saml:AudienceRestriction>";
        SamlVerificationResult both = new SamlCredentialVerifier().verify(withConditions(RESTRICTION + alsoApp),
                idpCert, AUDIENCE);
        assertTrue(both.isValid(), () -> String.valueOf(both.getErrors()));
        assertEquals(List.of(AUDIENCE, "https://only-this-one.example"), both.getAudiences());
    }

    /**
     * SAML Core §2.5.1.1: a condition that is not understood makes the assertion Indeterminate, and "An
     * assertion that is determined to be Invalid or Indeterminate MUST be rejected by a relying party".
     */
    @Test
    void aConditionThatIsNotUnderstoodIsRejected() throws Exception {
        String[] notUnderstood = {
                "<saml:Condition xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:x=\"urn:x\""
                        + " xsi:type=\"x:OnlyOnTuesdays\"/>",
                "<x:Whatever xmlns:x=\"urn:x\"/>",
                "<saml:ProxyRestriction Count=\"0\"/><saml:ProxyRestriction Count=\"1\"/>",
                "<saml:OneTimeUse/><saml:OneTimeUse/>",
                "<saml:AudienceRestriction/>",
                "<saml:AudienceRestriction><saml:Audience> </saml:Audience></saml:AudienceRestriction>"};
        for (String extra : notUnderstood) {
            SamlVerificationResult r = new SamlCredentialVerifier().verify(withConditions(RESTRICTION + extra),
                    idpCert, AUDIENCE);
            assertFalse(r.isValid(), extra);
            assertEquals(Boolean.FALSE, r.getChecks().get("conditionsUnderstood"), extra);
        }
        // One ProxyRestriction is understood, and always Valid (§2.5.1.6).
        SamlVerificationResult proxy = new SamlCredentialVerifier().verify(
                withConditions(RESTRICTION + "<saml:ProxyRestriction Count=\"0\"/>"), idpCert, AUDIENCE);
        assertTrue(proxy.isValid(), () -> String.valueOf(proxy.getErrors()));
        assertEquals(Boolean.TRUE, proxy.getChecks().get("conditionsUnderstood"));
    }

    /** The schema allows one {@code <Conditions>}; only the first used to be read, so a second was ignored. */
    @Test
    void aSecondConditionsIsRejected() throws Exception {
        String expired = "<saml:Conditions NotBefore=\"" + iso(-7200) + "\" NotOnOrAfter=\"" + iso(-3600) + "\">"
                + RESTRICTION + "</saml:Conditions>";
        String xml = responseTemplate(ALICE).replace("</saml:Conditions>", "</saml:Conditions>" + expired);
        SamlVerificationResult r = new SamlCredentialVerifier().verify(signed(xml), idpCert, AUDIENCE);
        assertFalse(r.isValid());
        assertEquals(Boolean.FALSE, r.getChecks().get("conditionsUnderstood"));
    }

    /**
     * SAML Core §2.5.1.5: a OneTimeUse assertion "MUST NOT be retained for future use". It is valid, and
     * the result says so, so a caller that caches verdicts knows not to cache this one.
     */
    @Test
    void oneTimeUseIsReported() throws Exception {
        SamlVerificationResult once = new SamlCredentialVerifier().verify(
                withConditions(RESTRICTION + "<saml:OneTimeUse/>"), idpCert, AUDIENCE);
        assertTrue(once.isValid(), () -> String.valueOf(once.getErrors()));
        assertEquals(Boolean.TRUE, once.getOneTimeUse());
        assertNull(new SamlCredentialVerifier().verify(signedResponse(ALICE), idpCert, AUDIENCE).getOneTimeUse());
    }

    // ------------------------------------------------- SAML Core §5 signature processing (R-22)

    private static final String VICTIM = "https://id.example/victim";

    private SamlVerificationResult verifySigned(Document doc) throws Exception {
        return new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);
    }

    /** SAML Core §5.4.2: "Signatures MUST contain a single {@code <ds:Reference>}". Two used to verify. */
    @Test
    void aSignatureMustHaveASingleReference() throws Exception {
        Document doc = parse(responseTemplate(ALICE));
        sign(assertionOf(doc), idpKeyPair.getPrivate(), SignatureMethod.RSA_SHA256, DigestMethod.SHA256,
                standardTransforms(), 1);
        SamlVerificationResult r = verifySigned(doc);
        assertFalse(r.isValid());
        assertEquals(Boolean.FALSE, r.getChecks().get("signatureCoversSignedElement"));
    }

    /**
     * SAML Core §5.4.4: a verifier allowing other transforms "MUST ensure that no content of the SAML
     * message is excluded from the signature". An XPath filter that leaves {@code <Subject>} out lets the
     * subject be replaced after signing; this used to verify, as the victim.
     */
    @Test
    void aTransformThatLeavesTheSubjectOutIsRejected() throws Exception {
        Document doc = parse(responseTemplate(ALICE));
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        List<Transform> leaveOutSubject = List.of(
                fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                fac.newTransform(Transform.XPATH, new XPathFilterParameterSpec(
                        "not(ancestor-or-self::saml:Subject)", Map.of("saml", NS))),
                fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null));
        sign(assertionOf(doc), idpKeyPair.getPrivate(), SignatureMethod.RSA_SHA256, DigestMethod.SHA256,
                leaveOutSubject, 0);
        doc.getElementsByTagNameNS(NS, "NameID").item(0).setTextContent(VICTIM);

        SamlVerificationResult r = verifySigned(doc);

        assertFalse(r.isValid(), "a subject the signature does not cover was accepted");
        assertNotEquals(VICTIM, r.getSubject());
        assertEquals(Boolean.FALSE, r.getChecks().get("signatureAlgorithmsAllowed"));
    }

    /** SHA-1 digests and signatures are refused whatever the XML-DSig provider allows, and so are small keys. */
    @Test
    void weakAlgorithmsAndKeysAreRejected() throws Exception {
        String[][] weak = {{SignatureMethod.RSA_SHA256, DigestMethod.SHA1}, {SignatureMethod.RSA_SHA1, DigestMethod.SHA256}};
        for (String[] algorithms : weak) {
            Document doc = parse(responseTemplate(ALICE));
            sign(assertionOf(doc), idpKeyPair.getPrivate(), algorithms[0], algorithms[1], standardTransforms(), 0);
            SamlVerificationResult r = verifySigned(doc);
            assertFalse(r.isValid(), String.join(" ", algorithms));
            assertEquals(Boolean.FALSE, r.getChecks().get("signatureAlgorithmsAllowed"), String.join(" ", algorithms));
        }

        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(1024);
        KeyPair small = g.generateKeyPair();
        Document doc = parse(responseTemplate(ALICE));
        signAssertion(doc, small.getPrivate());
        SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), selfSigned(small), AUDIENCE);
        assertFalse(r.isValid(), "RSA-1024");
        assertEquals(Boolean.FALSE, r.getChecks().get("certificateKeyStrong"));
    }

    /** Controls: an ECDSA P-256 IdP, and a Response signed as well as its assertion, both verify. */
    @Test
    void ecdsaAndSignedResponsesVerify() throws Exception {
        KeyPair ec = ecP256();
        Document ecDoc = parse(responseTemplate(ALICE));
        sign(assertionOf(ecDoc), ec.getPrivate(), SignatureMethod.ECDSA_SHA256, DigestMethod.SHA256,
                standardTransforms(), 0);
        SamlVerificationResult ecResult = new SamlCredentialVerifier().verify(serialize(ecDoc), selfSigned(ec), AUDIENCE);
        assertTrue(ecResult.isValid(), () -> String.valueOf(ecResult.getErrors()));
        assertEquals(Boolean.TRUE, ecResult.getChecks().get("certificateKeyStrong"));

        Document both = parse(responseTemplate(ALICE));
        signAssertion(both, idpKeyPair.getPrivate());
        sign(both.getDocumentElement(), idpKeyPair.getPrivate(), SignatureMethod.RSA_SHA256, DigestMethod.SHA256,
                standardTransforms(), 0);
        SamlVerificationResult r = verifySigned(both);
        assertTrue(r.isValid(), () -> String.valueOf(r.getErrors()));
        assertEquals(Boolean.TRUE, r.getChecks().get("signatureAlgorithmsAllowed"));
    }

    /**
     * SAML Profiles §4.1.4.3: "Verify any signatures present on the assertion(s) or the response". With
     * the Response signed, the assertion's own signature used to go unread — here, one by another key.
     */
    @Test
    void everySignaturePresentIsVerified() throws Exception {
        Document doc = parse(responseTemplate(ALICE));
        signAssertion(doc, rsa().getPrivate());
        sign(doc.getDocumentElement(), idpKeyPair.getPrivate(), SignatureMethod.RSA_SHA256, DigestMethod.SHA256,
                standardTransforms(), 0);
        SamlVerificationResult r = verifySigned(doc);
        assertFalse(r.isValid());
        assertEquals(Boolean.FALSE, r.getChecks().get("signatureValid"));
    }

    /** SAML Core §4.1.2: a relying party "MUST NOT process" an assertion of a major version it does not support. */
    @Test
    void onlySaml2IsProcessed() throws Exception {
        String xml = responseTemplate(ALICE);
        for (String other : new String[]{
                xml.replace("<saml:Assertion ID=\"a1\" Version=\"2.0\"", "<saml:Assertion ID=\"a1\" Version=\"3.0\""),
                xml.replace("ID=\"r1\" Version=\"2.0\"", "ID=\"r1\" Version=\"3.0\"")}) {
            assertNotEquals(xml, other);
            SamlVerificationResult r = new SamlCredentialVerifier().verify(signed(other), idpCert, AUDIENCE);
            assertFalse(r.isValid());
            assertEquals(Boolean.FALSE, r.getChecks().get("versionSupported"));
        }
    }

    /** An IssueInstant in the future was not written by a clock keeping time. 2099 used to verify. */
    @Test
    void anIssueInstantInTheFutureIsRejected() throws Exception {
        String xml = responseTemplate(ALICE);
        String later = " IssueInstant=\"2099-01-01T00:00:00Z\"";
        for (String other : new String[]{
                xml.replaceFirst("(<saml:Assertion ID=\"a1\" Version=\"2.0\") IssueInstant=\"[^\"]*\"", "$1" + later),
                xml.replaceFirst("(ID=\"r1\" Version=\"2.0\") IssueInstant=\"[^\"]*\"", "$1" + later)}) {
            assertNotEquals(xml, other);
            SamlVerificationResult r = new SamlCredentialVerifier().verify(signed(other), idpCert, AUDIENCE);
            assertFalse(r.isValid());
            assertEquals(Boolean.FALSE, r.getChecks().get("issueInstantValid"));
        }
    }

    /**
     * SAML Profiles §4.1.4.2: a Response's {@code <Issuer>} "MAY be omitted, but if present it MUST
     * contain the unique identifier of the issuing identity provider" — the assertion's.
     */
    @Test
    void aResponseIssuerMustBeTheAssertionsIssuer() throws Exception {
        String responseIssuer = "\"><saml:Issuer>https://idp.example</saml:Issuer><samlp:Status>";
        String xml = responseTemplate(ALICE);
        assertTrue(xml.contains(responseIssuer));
        SamlVerificationResult other = new SamlCredentialVerifier().verify(signed(xml.replace(responseIssuer,
                "\"><saml:Issuer>https://other-idp.example</saml:Issuer><samlp:Status>")), idpCert, AUDIENCE);
        assertFalse(other.isValid());
        assertEquals(Boolean.FALSE, other.getChecks().get("issuersMatch"));

        SamlVerificationResult omitted = new SamlCredentialVerifier().verify(signed(xml.replace(responseIssuer,
                "\"><samlp:Status>")), idpCert, AUDIENCE);
        assertTrue(omitted.isValid(), () -> String.valueOf(omitted.getErrors()));
    }

    // ------------------------------------------------------- trust out of band (R-25)

    private static final String ISSUER = "https://idp.example";

    private static IdentityProviderModel identityProvider(String alias, String providerId, String entityId,
                                                          boolean enabled, X509Certificate... certificates)
            throws Exception {
        IdentityProviderModel model = new IdentityProviderModel();
        model.setAlias(alias);
        model.setProviderId(providerId);
        model.setEnabled(enabled);
        List<String> encoded = new ArrayList<>();
        for (X509Certificate certificate : certificates) {
            encoded.add(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        }
        model.setConfig(new HashMap<>(Map.of("idpEntityId", entityId, "signingCertificate", String.join(",", encoded))));
        return model;
    }

    private static SamlTrust realm(IdentityProviderModel... identityProviders) {
        return new RealmIdentityProviders(() -> Stream.of(identityProviders));
    }

    private static SamlVerificationResult verify(String xml, SamlTrust trust) {
        return new SamlCredentialVerifier().verify(xml, trust, AUDIENCE, null, null, false);
    }

    private static String fingerprint(X509Certificate certificate) throws Exception {
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded());
        return java.util.HexFormat.ofDelimiter(":").withUpperCase().formatHex(digest);
    }

    /**
     * The suite: "there must be a trust relationship with the issuing identity provider … established
     * out-of-band". A realm's SAML identity provider is one: an entity ID and its signing certificates.
     */
    @Test
    void trustComesFromTheIdentityProviderForTheIssuer() throws Exception {
        SamlVerificationResult r = verify(signedResponse(ALICE),
                realm(identityProvider("partner-idp", "saml", ISSUER, true, idpCert)));
        assertTrue(r.isValid(), () -> String.valueOf(r.getErrors()));
        assertEquals("identity-provider", r.getTrustSource());
        assertEquals("partner-idp", r.getIdentityProvider());
        assertEquals(fingerprint(idpCert), r.getCertificateSha256());
        assertEquals(Boolean.TRUE, r.getChecks().get("trustedCertificateFound"));
    }

    /**
     * The hazard R-25 names: a relying party trying each certificate it trusts accepts IdP A signing an
     * assertion that says IdP B issued it, with B's user as the subject. Bound by entity ID, A's
     * certificate is not one trusted for B.
     */
    @Test
    void aCertificateTrustedForOneIssuerDoesNotVouchForAnother() throws Exception {
        String signedByA = signedResponse(ALICE); // Issuer is ISSUER, signed with A's key
        SamlTrust realm = realm(
                identityProvider("idp-a", "saml", "https://idp-a.example", true, idpCert),
                identityProvider("idp-b", "saml", ISSUER, true, selfSigned(rsa())));
        SamlVerificationResult r = verify(signedByA, realm);
        assertFalse(r.isValid());
        assertEquals(Boolean.FALSE, r.getChecks().get("signatureValid"));

        // A caller handing over A's certificate gets "valid" — and the result says whose certificate it was.
        SamlVerificationResult supplied = new SamlCredentialVerifier().verify(signedByA, idpCert, AUDIENCE);
        assertTrue(supplied.isValid());
        assertEquals("request", supplied.getTrustSource());
        assertNull(supplied.getIdentityProvider());
        assertEquals(fingerprint(idpCert), supplied.getCertificateSha256());
    }

    /** Only enabled SAML identity providers whose IdP entity ID is the issuer count. */
    @Test
    void anIssuerNoIdentityProviderNamesIsNotTrusted() throws Exception {
        SamlVerificationResult r = verify(signedResponse(ALICE), realm(
                identityProvider("elsewhere", "saml", "https://elsewhere.example", true, idpCert),
                identityProvider("switched-off", "saml", ISSUER, false, idpCert),
                identityProvider("not-saml", "oidc", ISSUER, true, idpCert)));
        assertFalse(r.isValid());
        assertEquals(Boolean.FALSE, r.getChecks().get("trustedCertificateFound"));
        assertNull(r.getTrustSource());
    }

    /** An IdP rotating keys has several certificates; each is tried, and the one that verified is named. */
    @Test
    void aRotatingIdentityProviderTriesEachCertificate() throws Exception {
        X509Certificate retired = certificate(idpKeyPair, -172_800_000L, -86_400_000L); // same key, expired
        SamlVerificationResult r = verify(signedResponse(ALICE), realm(identityProvider("partner-idp", "saml", ISSUER,
                true, retired, selfSigned(rsa()), idpCert)));
        assertTrue(r.isValid(), () -> String.valueOf(r.getErrors()));
        assertEquals(fingerprint(idpCert), r.getCertificateSha256());

        SamlVerificationResult onlyRetired = verify(signedResponse(ALICE),
                realm(identityProvider("partner-idp", "saml", ISSUER, true, retired)));
        assertFalse(onlyRetired.isValid(), "an expired certificate is not a trust anchor");
        assertEquals(Boolean.FALSE, onlyRetired.getChecks().get("certificateValid"));
    }

    /**
     * A caller can say which issuer and which Recipient it expects. A supplied certificate is otherwise
     * bound to no issuer, and Profiles §4.1.4.3 says to "Verify that the Recipient attribute … matches".
     */
    @Test
    void theExpectedIssuerAndRecipientAreEnforced() throws Exception {
        SamlTrust supplied = SamlTrust.certificate(idpCert);
        String xml = signedResponse(ALICE);
        SamlVerificationResult both = new SamlCredentialVerifier().verify(xml, supplied, AUDIENCE, ISSUER, AUDIENCE, false);
        assertTrue(both.isValid(), () -> String.valueOf(both.getErrors()));
        assertEquals(Boolean.TRUE, both.getChecks().get("issuerMatched"));
        assertEquals(Boolean.TRUE, both.getChecks().get("recipientMatched"));

        SamlVerificationResult issuer = new SamlCredentialVerifier().verify(xml, supplied, AUDIENCE,
                "https://other-idp.example", null, false);
        assertFalse(issuer.isValid());
        assertEquals(Boolean.FALSE, issuer.getChecks().get("issuerMatched"));

        SamlVerificationResult recipient = new SamlCredentialVerifier().verify(xml, supplied, AUDIENCE, null,
                "https://other-app.example/SAML", false);
        assertFalse(recipient.isValid());
        assertEquals(Boolean.FALSE, recipient.getChecks().get("recipientMatched"));
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
        Document doc = parse(responseTemplateNoExpiry(ALICE));
        signAssertion(doc, idpKeyPair.getPrivate());
        SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);
        assertFalse(r.isValid(), "an assertion with no Conditions/@NotOnOrAfter must be rejected");
        assertEquals(Boolean.FALSE, r.getChecks().get("withinValidityWindow"));
    }

    /**
     * P0-8: a Response that reports a failure status is not a credential, however well signed the
     * assertion it happens to carry is.
     */
    @Test
    void nonSuccessStatusRejected() throws Exception {
        Document doc = parse(responseTemplate(ALICE).replace(STATUS_SUCCESS, STATUS_RESPONDER));
        signAssertion(doc, idpKeyPair.getPrivate());
        SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);
        assertFalse(r.isValid(), "a Response whose StatusCode is not Success must be rejected");
        assertEquals(Boolean.FALSE, r.getChecks().get("statusSuccess"));
    }

    /** P0-8: a Response with no {@code <samlp:Status>} at all is equally not a success. */
    @Test
    void missingStatusRejected() throws Exception {
        Document doc = parse(responseTemplate(ALICE).replace(status(STATUS_SUCCESS), ""));
        signAssertion(doc, idpKeyPair.getPrivate());
        SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);
        assertFalse(r.isValid(), "a Response with no StatusCode must be rejected");
        assertEquals(Boolean.FALSE, r.getChecks().get("statusSuccess"));
    }

    /**
     * P0-7: a signature is only as good as the certificate it is checked against. An expired IdP
     * certificate is not a trust anchor, even though the maths still verifies.
     */
    @Test
    void expiredIdpCertificateRejected() throws Exception {
        KeyPair kp = rsa();
        X509Certificate expired = certificate(kp, -172_800_000L, -86_400_000L); // expired a day ago
        Document doc = parse(responseTemplate(ALICE));
        signAssertion(doc, kp.getPrivate());
        String xml = serialize(doc);

        SamlVerificationResult r = new SamlCredentialVerifier().verify(xml, expired, AUDIENCE);
        assertFalse(r.isValid(), "an expired IdP certificate must not be accepted as a trust anchor");
        assertEquals(Boolean.FALSE, r.getChecks().get("certificateValid"));

        // ...but an operator analysing an old credential offline can opt in explicitly.
        SamlVerificationResult allowed = new SamlCredentialVerifier().verify(xml, expired, AUDIENCE, true);
        assertTrue(allowed.isValid(), () -> "expected valid with the opt-in, errors: " + allowed.getErrors());
        assertEquals(Boolean.FALSE, allowed.getChecks().get("certificateValid"));
    }

    /** P0-9: the bearer SubjectConfirmationData window is enforced, not only {@code <Conditions>}. */
    @Test
    void expiredSubjectConfirmationRejected() throws Exception {
        Document doc = parse(withSubjectConfirmationExpiry(responseTemplate(ALICE), iso(-3600)));
        signAssertion(doc, idpKeyPair.getPrivate());
        SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);
        assertFalse(r.isValid(), "an expired bearer SubjectConfirmationData must be rejected");
        assertEquals(Boolean.FALSE, r.getChecks().get("subjectConfirmationWithinWindow"));
    }

    /** P0-9 / LWS SAML suite: Recipient carries the LWS client identifier, so it is required. */
    @Test
    void missingRecipientRejected() throws Exception {
        Document doc = parse(responseTemplate(ALICE).replace("Recipient=" + '"' + AUDIENCE + '"' + " ", ""));
        signAssertion(doc, idpKeyPair.getPrivate());
        SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);
        assertFalse(r.isValid(), "an assertion with no SubjectConfirmationData/@Recipient must be rejected");
        assertEquals(Boolean.FALSE, r.getChecks().get("recipientPresent"));
    }

    /** P0-9: only a bearer subject confirmation is an LWS credential. */
    @Test
    void nonBearerSubjectConfirmationRejected() throws Exception {
        Document doc = parse(responseTemplate(ALICE)
                .replace("urn:oasis:names:tc:SAML:2.0:cm:bearer", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"));
        signAssertion(doc, idpKeyPair.getPrivate());
        SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);
        assertFalse(r.isValid(), "a non-bearer SubjectConfirmation must be rejected");
        assertEquals(Boolean.FALSE, r.getChecks().get("bearerSubjectConfirmation"));
    }

    /**
     * P1-M1: "The SAML token MUST use the saml:Issuer assertion for the LWS issuer identifier", and
     * LWS core section 4.1 makes the issuer REQUIRED. It was recorded but never required.
     */
    @Test
    void missingIssuerRejected() throws Exception {
        Document doc = parse(responseTemplate(ALICE)
                .replace("<saml:Assertion ID=" + Q + "a1" + Q + " Version=" + Q + "2.0" + Q
                        + " IssueInstant=" + Q + iso(0) + Q + ">"
                        + "<saml:Issuer>https://idp.example</saml:Issuer>",
                         "<saml:Assertion ID=" + Q + "a1" + Q + " Version=" + Q + "2.0" + Q
                        + " IssueInstant=" + Q + iso(0) + Q + ">"));
        signAssertion(doc, idpKeyPair.getPrivate());
        SamlVerificationResult r = new SamlCredentialVerifier().verify(serialize(doc), idpCert, AUDIENCE);
        assertFalse(r.isValid(), "an assertion with no <Issuer> must be rejected");
        assertEquals(Boolean.FALSE, r.getChecks().get("issuerPresent"));
    }

    /** P1-K1/K2: the result names the LWS client (the Recipient) and the suite token type. */
    @Test
    void reportsClientAndTokenType() throws Exception {
        SamlVerificationResult r = new SamlCredentialVerifier().verify(signedResponse(ALICE), idpCert, AUDIENCE);
        assertTrue(r.isValid(), () -> "errors: " + r.getErrors());
        assertEquals(AUDIENCE, r.getClient());
        assertEquals("urn:ietf:params:oauth:token-type:saml2", r.getTokenType());
    }

    /** P0-4: a rejection carries a trace id, and never the underlying exception. */
    @Test
    void failureIsOpaqueButTraceable() {
        SamlVerificationResult r = new SamlCredentialVerifier().verify("not xml at all", idpCert, AUDIENCE);
        assertFalse(r.isValid());
        assertNotNull(r.getTraceId(), "a failed verification must carry a trace id");
        assertEquals(List.of("Credential could not be validated"), r.getErrors(),
                "the parser exception must not be reflected back to the caller");
    }

    // --------------------------------------------------------------------------- SAML construction

    private String signedResponse(String nameId) throws Exception {
        Document doc = parse(responseTemplate(nameId));
        signAssertion(doc, idpKeyPair.getPrivate());
        return serialize(doc);
    }

}
