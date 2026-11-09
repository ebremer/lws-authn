/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.saml.verify;

import static com.ebremer.lws.authn.saml.verify.SamlFixtures.NS;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.PROTOCOL_NS;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.iso;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.parse;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.rsa;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.selfSigned;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.serialize;
import static com.ebremer.lws.authn.saml.verify.SamlFixtures.standardTransforms;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.ebremer.lws.authn.saml.SamlConstants;

/**
 * The SAML suite's own example, as published in the Working Draft of 9 November 2026
 * (https://www.w3.org/TR/2026/WD-lws10-authn-saml-20261109/, Example 1), run through the verifier.
 *
 * <p>That edition's one change is to this example: its outer {@code </ds:Signature>} closing tag had been
 * printed as a second {@code </ds:SignedInfo>} (w3c/lws-protocol#298), so the example was not
 * well-formed XML. As now printed it parses, and it is used here as printed — the Response signed, the
 * assertion not, the NameID with whitespace around it, an audience restriction naming both the client
 * and the authorization server — with three changes, each something the example leaves to the reader:</p>
 *
 * <ul>
 *   <li>the {@code <ds:Signature>} whose {@code <ds:SignedInfo>} it abbreviates to "…" is a real one,
 *       made where the example has it (after the Response's {@code <Issuer>}), by an RSA-2048 IdP key;</li>
 *   <li>the Response and the assertion carry the {@code ID} attributes SAML Core §3.2.2 and §2.3.3
 *       require and the example leaves out, the Response's being what its signature references
 *       (§5.4.2);</li>
 *   <li>its October 2025 times are moved to now, an hour apart as they are in the example —
 *       {@link #theExampleAsPrintedFailsOnlyForItsDates} shows that is all that moving them changes.</li>
 * </ul>
 *
 * <p>Trust is the realm identity-provider kind: the certificate is trusted for {@code https://idp.example}
 * alone, so the example's {@code <Issuer>} has to be the one that certificate is bound to.</p>
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SamlSpecificationExampleTest {

    private static final String DSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String IDP = "https://idp.example";
    private static final String SUBJECT = "https://id.example/end-user";
    private static final String CLIENT = "https://app.example/SAML";
    private static final String AUTHORIZATION_SERVER = "https://as.example";

    /** Example 1 of the 9 November 2026 edition, as printed. */
    private static final String EXAMPLE = """
            <samlp:Response
                xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                Version="2.0"
                IssueInstant="2025-10-25T01:01:16Z">

              <saml:Issuer>https://idp.example</saml:Issuer>

              <ds:Signature>
                <ds:SignedInfo>
                  ...
                </ds:SignedInfo>
              </ds:Signature>

              <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
              </samlp:Status>

              <saml:Assertion Version="2.0" IssueInstant="2025-10-25T01:01:16Z">
                <saml:Issuer>https://idp.example</saml:Issuer>
                <saml:Subject>
                  <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
                      https://id.example/end-user
                  </saml:NameID>
                  <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData NotOnOrAfter="2025-10-25T02:01:16Z"
                                                  Recipient="https://app.example/SAML"/>
                  </saml:SubjectConfirmation>
                </saml:Subject>
                <saml:Conditions NotBefore="2025-10-25T01:01:16Z"
                                 NotOnOrAfter="2025-10-25T02:01:16Z">
                  <saml:AudienceRestriction>
                    <saml:Audience>https://app.example/SAML</saml:Audience>
                    <saml:Audience>https://as.example</saml:Audience>
                  </saml:AudienceRestriction>
                </saml:Conditions>
              </saml:Assertion>
            </samlp:Response>
            """;

    /** The example's two times: when it was issued and its window opens, and an hour later. */
    private static final String EXAMPLE_START = "2025-10-25T01:01:16Z";
    private static final String EXAMPLE_END = "2025-10-25T02:01:16Z";

    private KeyPair idpKey;
    private X509Certificate idpCertificate;
    private SamlTrust trust;

    @BeforeAll
    void identityProvider() throws Exception {
        idpKey = rsa();
        idpCertificate = selfSigned(idpKey);
        List<SamlTrust.TrustedCertificate> trusted = List.of(new SamlTrust.TrustedCertificate(idpCertificate,
                SamlTrust.SOURCE_IDENTITY_PROVIDER, "idp-example"));
        trust = issuer -> IDP.equals(issuer) ? trusted : List.of();
    }

    /**
     * The example as an IdP would send it: its placeholder signature replaced by a real one in the same
     * place, the two IDs added, and its times as given.
     */
    private String signedExample(String start, String end) throws Exception {
        String xml = EXAMPLE.replace(EXAMPLE_START, start).replace(EXAMPLE_END, end);
        Document doc = parse(xml);
        Element response = doc.getDocumentElement();
        Element placeholder = (Element) response.getElementsByTagNameNS(DSIG_NS, "Signature").item(0);
        Element status = (Element) response.getElementsByTagNameNS(PROTOCOL_NS, "Status").item(0);
        response.removeChild(placeholder);
        response.setAttribute("ID", "_example-response");
        response.setIdAttribute("ID", true);
        ((Element) response.getElementsByTagNameNS(NS, "Assertion").item(0)).setAttribute("ID", "_example-assertion");

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference reference = fac.newReference("#_example-response", fac.newDigestMethod(DigestMethod.SHA256, null),
                standardTransforms(), null, null);
        SignedInfo signedInfo = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                fac.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        fac.newXMLSignature(signedInfo, null).sign(new DOMSignContext(idpKey.getPrivate(), response, status));
        return serialize(doc);
    }

    private SamlVerificationResult verify(String xml, String audience) {
        return new SamlCredentialVerifier().verify(xml, trust, audience, IDP, CLIENT, false);
    }

    private static Map<String, Boolean> failed(SamlVerificationResult result) {
        Map<String, Boolean> failed = new java.util.LinkedHashMap<>(result.getChecks());
        failed.values().removeIf(Boolean.TRUE::equals);
        return failed;
    }

    /** The example still parses once its placeholder is filled in: the closing tag #298 corrected. */
    @Test
    void theExampleIsWellFormedXml() throws Exception {
        Document doc = parse(EXAMPLE);
        assertEquals("Response", doc.getDocumentElement().getLocalName());
        assertEquals(1, doc.getElementsByTagNameNS(DSIG_NS, "Signature").getLength());
        assertEquals(1, doc.getElementsByTagNameNS(NS, "Assertion").getLength());
    }

    /**
     * Signed, the example verifies for the authorization server it names, from the issuer it names, for
     * the client its {@code Recipient} names, and the result reports the suite's subject ({@code NameID},
     * whitespace trimmed), issuer, client identifier and token type identifier.
     */
    @Test
    void theSignedExampleVerifies() throws Exception {
        SamlVerificationResult result = verify(signedExample(iso(0), iso(3600)), AUTHORIZATION_SERVER);

        assertTrue(result.isValid(), () -> result.getErrors() + " " + result.getChecks());
        assertTrue(failed(result).isEmpty(), () -> String.valueOf(result.getChecks()));
        assertEquals(SUBJECT, result.getSubject());
        assertEquals("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", result.getSubjectFormat());
        assertEquals(IDP, result.getIssuer());
        assertEquals(CLIENT, result.getClient());
        assertEquals(CLIENT, result.getRecipient());
        assertEquals(List.of(CLIENT, AUTHORIZATION_SERVER), result.getAudiences());
        assertEquals(SamlConstants.TOKEN_TYPE_SAML2, result.getTokenType());
        assertEquals(SamlTrust.SOURCE_IDENTITY_PROVIDER, result.getTrustSource());
        for (String check : new String[]{"statusSuccess", "versionSupported", "signaturePresent",
                "signatureCoversSignedElement", "signatureAlgorithmsAllowed", "trustedCertificateFound",
                "signatureValid", "subjectIsUri", "issuerPresent", "issuerWellFormed", "issuersMatch",
                "issuerMatched", "recipientPresent", "recipientMatched", "subjectConfirmationWithinWindow",
                "conditionsUnderstood", "withinValidityWindow", "audienceMatched"}) {
            assertEquals(Boolean.TRUE, result.getChecks().get(check), check);
        }
    }

    /**
     * With its own times the signed example is an assertion whose bearer confirmation lapsed in October
     * 2025, and that is the one check that fails.
     */
    @Test
    void theExampleAsPrintedFailsOnlyForItsDates() throws Exception {
        SamlVerificationResult result = verify(signedExample(EXAMPLE_START, EXAMPLE_END), AUTHORIZATION_SERVER);

        assertFalse(result.isValid());
        assertEquals(Map.of("subjectConfirmationWithinWindow", false), failed(result), () -> result.getErrors().toString());
        assertEquals(Boolean.TRUE, result.getChecks().get("signatureValid"));
    }

    /** The example's audience restriction names {@code https://as.example}; it is not for another one. */
    @Test
    void theExampleIsNotValidForAnotherAuthorizationServer() throws Exception {
        SamlVerificationResult result = verify(signedExample(iso(0), iso(3600)), "https://other-as.example");

        assertFalse(result.isValid());
        assertEquals(Map.of("audienceMatched", false), failed(result), () -> result.getErrors().toString());
    }

    /** Signed by a key the issuer's trust does not hold, the example is refused at the signature. */
    @Test
    void theExampleSignedByAnotherKeyIsRefused() throws Exception {
        KeyPair genuine = idpKey;
        idpKey = rsa();
        String forged;
        try {
            forged = signedExample(iso(0), iso(3600));
        } finally {
            idpKey = genuine;
        }
        SamlVerificationResult result = verify(forged, AUTHORIZATION_SERVER);

        assertFalse(result.isValid());
        assertEquals(Map.of("signatureValid", false), failed(result), () -> result.getErrors().toString());
    }
}
