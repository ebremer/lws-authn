/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.saml.verify;

import static com.ebremer.lws.authn.saml.verify.SamlFixtures.ALICE;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.AUDIENCE;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.NS;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.assertionOf;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.certificate;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.iso;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.parse;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.responseTemplate;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.rsa;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.selfSigned;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.serialize;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.sign;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.signAssertion;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.signReferencing;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.standardTransforms;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * R-44: a negative test for each rule of the SAML verifier that had none — so that deleting the rule
 * fails a test, rather than leaving a verifier that silently accepts. Each case changes one thing about
 * a credential that otherwise verifies, and asserts the check that refuses it by name.
 *
 * <p>The signed-Response branch is here too: every other test signs the assertion, so a Response signed
 * over the whole message — the other way an IdP may sign, SAML Core §5.3 — had never been verified.</p>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SamlVerifierRulesTest {

    private static final String DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String VICTIM = "https://id.example/victim";
    private static final String OTHER_AUDIENCE = "https://other-app.example/SAML";
    private static final String RESTRICTION = "<saml:AudienceRestriction><saml:Audience>" + AUDIENCE
            + "</saml:Audience></saml:AudienceRestriction>";

    private KeyPair idpKeyPair;
    private X509Certificate idpCert;

    @BeforeAll
    void keys() throws Exception {
        idpKeyPair = rsa();
        idpCert = selfSigned(idpKeyPair);
    }

    // ------------------------------------------------------------------------------------ helpers

    /** {@code xml} with its assertion signed by the trusted IdP key. */
    private String signed(String xml) throws Exception {
        Document doc = parse(xml);
        signAssertion(doc, idpKeyPair.getPrivate());
        return serialize(doc);
    }

    private SamlVerificationResult verify(String xml) {
        return verify(xml, AUDIENCE);
    }

    private SamlVerificationResult verify(String xml, String expectedAudience) {
        return new SamlCredentialVerifier().verify(xml, idpCert, expectedAudience);
    }

    /** Refused, and by {@code check}. */
    private static void assertRefusedBy(String check, SamlVerificationResult r, String context) {
        assertFalse(r.isValid(), () -> context + ": accepted");
        assertEquals(Boolean.FALSE, r.getChecks().get(check),
                () -> context + ": not refused by " + check + "; checks " + r.getChecks() + ", errors " + r.getErrors());
    }

    private static void assertRefusedBy(String check, SamlVerificationResult r) {
        assertRefusedBy(check, r, check);
    }

    /** Refused, with an error that says {@code why}: for the structural rules, which record no check. */
    private static void assertRefusedSaying(String why, SamlVerificationResult r, String context) {
        assertFalse(r.isValid(), () -> context + ": accepted");
        assertTrue(r.getErrors().stream().anyMatch(e -> e.contains(why)),
                () -> context + ": expected an error saying '" + why + "', got " + r.getErrors());
    }

    private static void assertVerifies(SamlVerificationResult r, String context) {
        assertTrue(r.isValid(), () -> context + ": " + r.getErrors());
    }

    /** {@code xml} with the first match of {@code regex} replaced, failing if nothing matched. */
    private static String replacing(String xml, String regex, String replacement) {
        String out = xml.replaceFirst(regex, replacement);
        assertNotEquals(xml, out, regex);
        return out;
    }

    /** The template with its {@code <Conditions>} window set; {@code null} leaves an attribute out. */
    private static String withConditionsWindow(String notBefore, String notOnOrAfter) {
        return replacing(responseTemplate(ALICE), "<saml:Conditions [^>]*>", "<saml:Conditions"
                + attribute("NotBefore", notBefore) + attribute("NotOnOrAfter", notOnOrAfter) + ">");
    }

    /** The template with its {@code <SubjectConfirmationData>} replaced by one carrying {@code attributes}. */
    private static String withSubjectConfirmationData(String attributes) {
        return replacing(responseTemplate(ALICE), "<saml:SubjectConfirmationData [^>]*/>",
                "<saml:SubjectConfirmationData " + attributes + "/>");
    }

    private static String attribute(String name, String value) {
        return value == null ? "" : " " + name + "=\"" + value + "\"";
    }

    /** The template's assertion on its own, as the document root. */
    private static String bareAssertion() {
        String xml = responseTemplate(ALICE);
        String assertion = xml.substring(xml.indexOf("<saml:Assertion "), xml.indexOf("</samlp:Response>"));
        return assertion.replaceFirst("<saml:Assertion ", "<saml:Assertion xmlns:saml=\"" + NS + "\" ");
    }

    /** Signs the Response itself — the whole message — with an enveloped signature, as an IdP may. */
    private static void signResponse(Document doc, PrivateKey key) throws Exception {
        sign(doc.getDocumentElement(), key, SignatureMethod.RSA_SHA256, DigestMethod.SHA256, standardTransforms(), 0);
    }

    // ----------------------------------------------------------------- signatures (SAML Core §5.4)

    /**
     * R-44, {@code signaturePresent}. The suite's credential is a signed assertion, and Profiles §4.1.4.3
     * says to "Verify any signatures present on the assertion(s) or the response": with none present
     * there is nothing to verify, and an unsigned credential — Response or bare Assertion — is anyone's.
     */
    @Test
    void anUnsignedCredentialIsRefused() throws Exception {
        assertRefusedBy("signaturePresent", verify(responseTemplate(ALICE)), "unsigned Response");
        assertRefusedBy("signaturePresent", verify(bareAssertion()), "unsigned bare Assertion");

        SamlVerificationResult signed = verify(signed(responseTemplate(ALICE)));
        assertVerifies(signed, "control");
        assertEquals(Boolean.TRUE, signed.getChecks().get("signaturePresent"));
    }

    /** R-44. The other shape a credential may take, an Assertion as the document root, verifies when signed. */
    @Test
    void aBareSignedAssertionVerifies() throws Exception {
        SamlVerificationResult r = verify(signed(bareAssertion()));
        assertVerifies(r, "bare signed Assertion");
        assertEquals(ALICE, r.getSubject());
        assertNull(r.getChecks().get("statusSuccess"), "a bare assertion has no Response status to check");
    }

    /**
     * R-44, {@code signatureCoversSignedElement}. SAML Core §5.4.2: "Signatures MUST contain a single
     * {@code <ds:Reference>} containing a same-document reference to the ID attribute value of the root
     * element of the assertion or protocol message being signed". Every one of these is a well-formed
     * signature by the trusted key; none covers exactly the element it sits in.
     */
    @Test
    void aSignatureMustCoverExactlyTheElementItIsIn() throws Exception {
        PrivateKey key = idpKeyPair.getPrivate();

        Document theResponse = parse(responseTemplate(ALICE));
        signReferencing(theResponse, assertionOf(theResponse), "#r1", key);
        assertRefusedBy("signatureCoversSignedElement", verify(serialize(theResponse)),
                "an assertion's signature over the Response around it");

        Document wholeDocument = parse(responseTemplate(ALICE));
        signReferencing(wholeDocument, assertionOf(wholeDocument), "", key);
        assertRefusedBy("signatureCoversSignedElement", verify(serialize(wholeDocument)),
                "an assertion's signature over the whole document");

        // With no ID there is nothing for a reference to name. This one is refused while the signature is
        // read — the reading binds the element's ID — so before any check is recorded.
        Document noId = parse(responseTemplate(ALICE).replace("<saml:Assertion ID=\"a1\" ", "<saml:Assertion "));
        signReferencing(noId, assertionOf(noId), "", key);
        SamlVerificationResult unidentified = verify(serialize(noId));
        assertFalse(unidentified.isValid(), "a signed assertion with no ID");
        assertNull(unidentified.getChecks().get("signatureValid"));
        assertNull(unidentified.getSubject());

        Document twice = parse(responseTemplate(ALICE));
        signAssertion(twice, key);
        signAssertion(twice, key);
        assertRefusedBy("signatureCoversSignedElement", verify(serialize(twice)), "two signatures on one assertion");
    }

    // ------------------------------------------------- the signed Response (SAML Core §5.3, no test before)

    /**
     * R-44. SAML Core §5.3: a signature on a Response covers everything in it, the assertion included, so
     * the assertion need not carry a signature of its own. This branch had no test at all.
     */
    @Test
    void aSignedResponseCoversAnUnsignedAssertion() throws Exception {
        Document doc = parse(responseTemplate(ALICE));
        signResponse(doc, idpKeyPair.getPrivate());
        assertEquals(0, assertionOf(doc).getElementsByTagNameNS(DSIG_NS, "Signature").getLength());

        SamlVerificationResult r = verify(serialize(doc));

        assertVerifies(r, "a signed Response around an unsigned assertion");
        assertEquals(ALICE, r.getSubject());
        assertEquals(Boolean.TRUE, r.getChecks().get("signaturePresent"));
        assertEquals(Boolean.TRUE, r.getChecks().get("signatureCoversSignedElement"));
        assertEquals(Boolean.TRUE, r.getChecks().get("signatureValid"));
    }

    /**
     * R-44, {@code signatureValid}, for the signed Response: the assertion inside changed after signing,
     * the signature value altered, the Response signed by a key nobody trusts, and — with the assertion
     * properly signed — the Response around it signed by another key. Profiles §4.1.4.3: "Verify any
     * signatures present on the assertion(s) or the response".
     */
    @Test
    void aSignedResponseWhoseSignatureDoesNotHoldIsRefused() throws Exception {
        Document tampered = parse(responseTemplate(ALICE));
        signResponse(tampered, idpKeyPair.getPrivate());
        tampered.getElementsByTagNameNS(NS, "NameID").item(0).setTextContent(VICTIM);
        SamlVerificationResult r = verify(serialize(tampered));
        assertRefusedBy("signatureValid", r, "a subject changed after the Response was signed");
        assertNotEquals(VICTIM, r.getSubject());

        Document altered = parse(responseTemplate(ALICE));
        signResponse(altered, idpKeyPair.getPrivate());
        Element value = (Element) altered.getElementsByTagNameNS(DSIG_NS, "SignatureValue").item(0);
        String bits = value.getTextContent().trim();
        value.setTextContent((bits.charAt(0) == 'A' ? "B" : "A") + bits.substring(1));
        assertRefusedBy("signatureValid", verify(serialize(altered)), "an altered SignatureValue");

        Document untrusted = parse(responseTemplate(ALICE));
        signResponse(untrusted, rsa().getPrivate());
        assertRefusedBy("signatureValid", verify(serialize(untrusted)), "a Response signed by an untrusted key");

        Document mixed = parse(responseTemplate(ALICE));
        signAssertion(mixed, idpKeyPair.getPrivate());
        signResponse(mixed, rsa().getPrivate());
        assertRefusedBy("signatureValid", verify(serialize(mixed)),
                "a trusted assertion inside a Response signed by another key");
    }

    /**
     * R-44, {@code signatureCoversSignedElement}, for the signed Response: a signature on the Response that
     * names only the assertion leaves the Response's own {@code <Status>} and {@code <Issuer>} unsigned,
     * and one over the whole document by an empty reference is not §5.4.2's same-document reference to
     * the Response's ID.
     */
    @Test
    void aResponseSignatureThatCoversSomethingElseIsRefused() throws Exception {
        Document onlyTheAssertion = parse(responseTemplate(ALICE));
        signReferencing(onlyTheAssertion, onlyTheAssertion.getDocumentElement(), "#a1", idpKeyPair.getPrivate());
        assertRefusedBy("signatureCoversSignedElement", verify(serialize(onlyTheAssertion)),
                "a Response signature over only the assertion");

        Document wholeDocument = parse(responseTemplate(ALICE));
        signReferencing(wholeDocument, wholeDocument.getDocumentElement(), "", idpKeyPair.getPrivate());
        assertRefusedBy("signatureCoversSignedElement", verify(serialize(wholeDocument)),
                "a Response signature by an empty reference");
    }

    // --------------------------------------------------------------------- one assertion (R-31)

    /**
     * R-44, {@code singleAssertion}: a Response with no assertion is not a credential, and one with a
     * second assertion inside the signed one's {@code <Advice>} — signed along with it, so every
     * signature holds — gives a consumer that takes the first {@code Assertion} element the wrong one.
     */
    @Test
    void aResponseMustHoldExactlyOneAssertion() throws Exception {
        String xml = responseTemplate(ALICE);
        String none = xml.substring(0, xml.indexOf("<saml:Assertion ")) + "</samlp:Response>";
        assertRefusedBy("singleAssertion", verify(none), "a Response with no assertion");

        String advised = "<saml:Assertion ID=\"a3\" Version=\"2.0\" IssueInstant=\"" + iso(0) + "\">"
                + "<saml:Issuer>https://idp.example</saml:Issuer>"
                + "<saml:Subject><saml:NameID>" + VICTIM + "</saml:NameID></saml:Subject></saml:Assertion>";
        String inAdvice = xml.replace("</saml:Conditions>", "</saml:Conditions><saml:Advice>" + advised + "</saml:Advice>");
        assertNotEquals(xml, inAdvice);
        SamlVerificationResult r = verify(signed(inAdvice));
        assertRefusedBy("singleAssertion", r, "an assertion inside the signed assertion's <Advice>");
        assertNotEquals(VICTIM, r.getSubject());
    }

    // ------------------------------------------------------------------- validity windows (§2.5.1.2)

    /**
     * R-44, {@code withinValidityWindow}. SAML Core §2.5.1.2: NotOnOrAfter "Specifies the time instant at
     * which the assertion has expired". Only a missing NotOnOrAfter was tested; one in the past was not.
     */
    @Test
    void anExpiredAssertionIsRefused() throws Exception {
        assertRefusedBy("withinValidityWindow", verify(signed(withConditionsWindow(iso(-7200), iso(-3600)))));
        assertRefusedBy("withinValidityWindow", verify(signed(withConditionsWindow(null, iso(-3600)))),
                "expired, with no NotBefore");
    }

    /**
     * R-44, {@code withinValidityWindow}. SAML Core §2.5.1.2: NotBefore "Specifies the earliest time instant
     * at which the assertion is valid".
     */
    @Test
    void anAssertionNotYetValidIsRefused() throws Exception {
        assertRefusedBy("withinValidityWindow", verify(signed(withConditionsWindow(iso(3600), iso(7200)))));
        assertVerifies(verify(signed(withConditionsWindow(null, iso(3600)))), "no NotBefore: valid from the start");
    }

    /**
     * R-44, {@code subjectConfirmationWithinWindow}. Profiles §4.1.4.2: a bearer
     * {@code <SubjectConfirmationData>} carries "a NotOnOrAfter attribute that limits the window during
     * which the assertion can be delivered". Only an expired one was tested. The same section says it
     * "MUST NOT contain a NotBefore attribute"; this verifier tolerates one, but never one in the future.
     */
    @Test
    void aSubjectConfirmationOutsideItsWindowIsRefused() throws Exception {
        String recipient = "Recipient=\"" + AUDIENCE + "\"";
        assertRefusedBy("subjectConfirmationWithinWindow", verify(signed(withSubjectConfirmationData(recipient))),
                "no NotOnOrAfter");
        assertRefusedBy("subjectConfirmationWithinWindow", verify(signed(withSubjectConfirmationData(recipient
                + attribute("NotBefore", iso(3600)) + attribute("NotOnOrAfter", iso(7200))))), "NotBefore in the future");
    }

    /**
     * R-44. A timestamp that does not parse is refused, never read as "no limit" — and never leniently: a
     * lenient reader would take 30 February 2099 for 2 March 2099, an expiry still decades away.
     */
    @Test
    void unreadableTimestampsAreRefused() throws Exception {
        for (String unreadable : new String[]{"tomorrow", "2099-02-30T00:00:00Z"}) {
            Map<String, String[]> cases = new LinkedHashMap<>();
            cases.put("Conditions NotOnOrAfter", new String[]{"withinValidityWindow",
                    withConditionsWindow(iso(-60), unreadable)});
            cases.put("Conditions NotBefore", new String[]{"withinValidityWindow",
                    withConditionsWindow(unreadable, iso(3600))});
            cases.put("SubjectConfirmationData NotOnOrAfter", new String[]{"subjectConfirmationWithinWindow",
                    withSubjectConfirmationData("Recipient=\"" + AUDIENCE + "\"" + attribute("NotOnOrAfter", unreadable))});
            cases.put("Assertion IssueInstant", new String[]{"issueInstantValid", replacing(responseTemplate(ALICE),
                    "(<saml:Assertion ID=\"a1\" Version=\"2.0\") IssueInstant=\"[^\"]*\"", "$1" + attribute("IssueInstant", unreadable))});
            cases.put("Response IssueInstant", new String[]{"issueInstantValid", replacing(responseTemplate(ALICE),
                    "(ID=\"r1\" Version=\"2.0\") IssueInstant=\"[^\"]*\"", "$1" + attribute("IssueInstant", unreadable))});
            for (Map.Entry<String, String[]> c : cases.entrySet()) {
                assertRefusedBy(c.getValue()[0], verify(signed(c.getValue()[1])), c.getKey() + "=" + unreadable);
            }
        }
        assertRefusedBy("issueInstantValid", verify(signed(replacing(responseTemplate(ALICE),
                "(<saml:Assertion ID=\"a1\" Version=\"2.0\") IssueInstant=\"[^\"]*\"", "$1"))), "no IssueInstant");
    }

    // ------------------------------------------------------------------------------- the subject

    /** R-44. An empty {@code <NameID>} names nobody, and is refused before it is read as a URI. */
    @Test
    void anEmptyNameIdIsRefused() throws Exception {
        for (String empty : new String[]{"", "   "}) {
            SamlVerificationResult r = verify(signed(responseTemplate(empty)));
            assertRefusedSaying("Assertion <NameID> subject is empty", r, "'" + empty + "'");
            assertNull(r.getChecks().get("subjectIsUri"));
        }
    }

    /**
     * R-44. One {@code <Subject>}, holding one {@code <NameID>} and one {@code <SubjectConfirmation>}: with
     * two of either there is no single subject, or no single LWS client identifier, to report. (Profiles
     * §4.1.4.2 lets a bearer assertion carry several confirmations; this verifier takes only one, and
     * says so.)
     */
    @Test
    void theSubjectMustBeOneNameIdAndOneConfirmation() throws Exception {
        String xml = responseTemplate(ALICE);
        String subject = xml.substring(xml.indexOf("<saml:Subject>"), xml.indexOf("</saml:Subject>") + "</saml:Subject>".length());
        String nameId = xml.substring(xml.indexOf("<saml:NameID "), xml.indexOf("<saml:SubjectConfirmation "));
        String confirmation = xml.substring(xml.indexOf("<saml:SubjectConfirmation "), xml.indexOf("</saml:Subject>"));

        Map<String, String[]> cases = new LinkedHashMap<>();
        cases.put("no Subject", new String[]{"<Subject>", xml.replace(subject, "")});
        cases.put("no NameID", new String[]{"<NameID>", xml.replace(nameId, "")});
        cases.put("two NameIDs", new String[]{"<NameID>", xml.replace(nameId, nameId + nameId)});
        cases.put("no SubjectConfirmation", new String[]{"<SubjectConfirmation>", xml.replace(confirmation, "")});
        cases.put("two SubjectConfirmations", new String[]{"<SubjectConfirmation>",
                xml.replace(confirmation, confirmation + confirmation)});
        for (Map.Entry<String, String[]> c : cases.entrySet()) {
            assertNotEquals(xml, c.getValue()[1], c.getKey());
            assertRefusedSaying("Expected exactly one " + c.getValue()[0], verify(signed(c.getValue()[1])), c.getKey());
        }
    }

    /**
     * R-44, {@code recipientPresent}. A bearer {@code <SubjectConfirmation>} with no
     * {@code <SubjectConfirmationData>} has no Recipient — the LWS client identifier — and no delivery
     * window (Profiles §4.1.4.2).
     */
    @Test
    void aSubjectConfirmationWithoutDataIsRefused() throws Exception {
        String xml = replacing(responseTemplate(ALICE), "<saml:SubjectConfirmationData [^>]*/>", "");
        assertRefusedBy("recipientPresent", verify(signed(xml)));
    }

    // ---------------------------------------------------------------------------------- audience

    /**
     * R-44, {@code audienceMatched}. SAML Core §2.5.1.4: the assertion is addressed only to the audiences
     * its {@code <AudienceRestriction>} names. Every other test asked for the audience the template names.
     */
    @Test
    void anAudienceTheAssertionDoesNotNameIsRefused() throws Exception {
        assertRefusedBy("audienceMatched", verify(signed(responseTemplate(ALICE)), OTHER_AUDIENCE),
                "another relying party's assertion");

        String unrestricted = signed(responseTemplate(ALICE).replace(RESTRICTION, ""));
        assertRefusedBy("audienceMatched", verify(unrestricted, AUDIENCE), "an assertion restricted to no audience");
    }

    /**
     * R-44, {@code audiencePresent}. With no audience expected — none in the request, none configured — an
     * {@code <AudienceRestriction>} is still required: Profiles §4.1.4.2, "The assertion(s) containing a
     * bearer subject confirmation MUST contain an {@code <AudienceRestriction>}" (COMPLIANCE divergence 11).
     */
    @Test
    void withNoAudienceExpectedARestrictionIsStillRequired() throws Exception {
        String restricted = signed(responseTemplate(ALICE));
        String unrestricted = signed(responseTemplate(ALICE).replace(RESTRICTION, ""));
        for (String none : new String[]{null, "", "  "}) {
            assertRefusedBy("audiencePresent", verify(unrestricted, none), "expected audience '" + none + "'");

            SamlVerificationResult r = verify(restricted, none);
            assertVerifies(r, "expected audience '" + none + "'");
            assertEquals(Boolean.TRUE, r.getChecks().get("audiencePresent"));
            assertNull(r.getChecks().get("audienceMatched"), "there was nothing to match");
        }
    }

    // ---------------------------------------------------------------------- the IdP certificate

    /**
     * R-44, {@code certificateValid}. A certificate that is not yet valid is no more a trust anchor than an
     * expired one; only the expired case was tested (P0-7). The offline opt-in admits both.
     */
    @Test
    void aCertificateNotYetValidIsRefused() throws Exception {
        KeyPair kp = rsa();
        X509Certificate future = certificate(kp, 86_400_000L, 172_800_000L); // valid from tomorrow
        Document doc = parse(responseTemplate(ALICE));
        signAssertion(doc, kp.getPrivate());
        String xml = serialize(doc);

        assertRefusedBy("certificateValid", new SamlCredentialVerifier().verify(xml, future, AUDIENCE));

        SamlVerificationResult offline = new SamlCredentialVerifier().verify(xml, future, AUDIENCE, true);
        assertVerifies(offline, "with allowExpiredCertificate");
        assertEquals(Boolean.FALSE, offline.getChecks().get("certificateValid"));
    }
}
