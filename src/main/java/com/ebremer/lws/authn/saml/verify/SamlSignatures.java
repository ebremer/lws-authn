/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * SAML Core §5.4's XML Signature profile, applied with the JDK's XML Digital Signature API (JSR 105).
 */
package com.ebremer.lws.authn.saml.verify;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Set;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;

import org.w3c.dom.Element;

/**
 * Checks one enveloped {@code <ds:Signature>} on a SAML Response or Assertion.
 *
 * <p>This used to be Keycloak's {@code AssertionUtil.isSignatureValid}, which validates the XML signature
 * but not SAML Core §5.4's profile of it, so a signature with two references verified, and so did one
 * whose XPath transform left {@code <Subject>} out of what was signed — after which the subject could be
 * replaced (R-22). The profile is applied here first, from the parsed signature and before any
 * cryptography; then the signature is validated against the trusted key alone, whatever
 * {@code <ds:KeyInfo>} says.</p>
 *
 * @author Erich Bremer
 */
final class SamlSignatures {

    private SamlSignatures() {
    }

    /**
     * Signature algorithms accepted: RSA PKCS#1 v1.5 and RSA-PSS with SHA-2, and ECDSA with SHA-2. Not
     * {@code rsa-sha1}, which SAML Core §5.4.1 names as the one to support and which no longer resists
     * collisions; what verifies otherwise depended on the XML-DSig provider and the JVM's policy.
     */
    static final Set<String> SIGNATURE_METHODS = Set.of(
            SignatureMethod.RSA_SHA256, SignatureMethod.RSA_SHA384, SignatureMethod.RSA_SHA512,
            SignatureMethod.SHA256_RSA_MGF1, SignatureMethod.SHA384_RSA_MGF1, SignatureMethod.SHA512_RSA_MGF1,
            SignatureMethod.ECDSA_SHA256, SignatureMethod.ECDSA_SHA384, SignatureMethod.ECDSA_SHA512);

    /** Digest algorithms accepted: SHA-2. */
    static final Set<String> DIGEST_METHODS = Set.of(
            DigestMethod.SHA256, DigestMethod.SHA384, DigestMethod.SHA512);

    /**
     * SAML Core §5.4.4: "Signatures in SAML messages SHOULD NOT contain transforms other than the
     * enveloped signature transform … or the exclusive canonicalization transforms", and a verifier
     * that allows others "MUST ensure that no content of the SAML message is excluded from the
     * signature". This one does not allow others.
     */
    static final Set<String> TRANSFORMS = Set.of(Transform.ENVELOPED,
            CanonicalizationMethod.EXCLUSIVE, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS);

    /**
     * Canonicalizations of {@code <ds:SignedInfo>} accepted. SAML Core §5.4.3 says exclusive SHOULD be
     * used; inclusive canonicalization of {@code SignedInfo} leaves nothing out of the signature, so it
     * is accepted too.
     */
    static final Set<String> CANONICALIZATIONS = Set.of(
            CanonicalizationMethod.EXCLUSIVE, CanonicalizationMethod.EXCLUSIVE_WITH_COMMENTS,
            CanonicalizationMethod.INCLUSIVE, CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS);

    /** The smallest RSA modulus, in bits, accepted for an IdP key. */
    static final int MIN_RSA_BITS = 2048;

    /** The smallest elliptic-curve field, in bits, accepted for an IdP key: P-256. */
    static final int MIN_EC_BITS = 256;

    /**
     * Why {@code key} is not strong enough to trust, or {@code null} if it is: RSA of at least 2048
     * bits, or EC on a curve of at least 256. With an XML-DSig provider that allowed them, {@code rsa-sha1}
     * and a 512-bit RSA IdP key verified, and the JDK's own policy allows RSA-1024 (R-22).
     */
    static String keyProblem(PublicKey key) {
        if (key instanceof RSAPublicKey rsa) {
            int bits = rsa.getModulus().bitLength();
            return bits >= MIN_RSA_BITS ? null : "an RSA key of " + bits + " bits, below " + MIN_RSA_BITS;
        }
        if (key instanceof ECPublicKey ec) {
            int bits = ec.getParams().getCurve().getField().getFieldSize();
            return bits >= MIN_EC_BITS ? null : "an EC key of " + bits + " bits, below " + MIN_EC_BITS;
        }
        return "a " + (key == null ? "missing" : key.getAlgorithm()) + " key, which is neither RSA nor EC";
    }

    /**
     * Reads {@code signature} without validating it, to inspect what it signs and how. Nothing is
     * computed — no transform runs — so the JDK's secure validation mode, which would refuse a SHA-1
     * digest here with an exception rather than a reason, is left to {@link #validate}; the allow-lists
     * below say what is wrong instead.
     */
    static XMLSignature read(Element signature, Element signed) throws MarshalException {
        return XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context(NO_KEY, signature, signed, false));
    }

    /**
     * Why {@code signature} does not cover exactly {@code signed}, or {@code null} if it does. SAML Core
     * §5.4.2: "Signatures MUST contain a single {@code <ds:Reference>} containing a same-document
     * reference to the ID attribute value of the root element of the assertion or protocol message
     * being signed".
     */
    static String coverageProblem(XMLSignature signature, Element signed) {
        String id = signed.getAttribute("ID");
        if (id.isEmpty()) {
            return "the signed element has no ID";
        }
        List<Reference> references = signature.getSignedInfo().getReferences();
        if (references.size() != 1) {
            return "a signature must contain a single <ds:Reference>, and this one has " + references.size();
        }
        if (!("#" + id).equals(references.get(0).getURI())) {
            return "the <ds:Reference> does not name the signed element's ID";
        }
        return null;
    }

    /** Why {@code signature}'s algorithms or transforms are not accepted, or {@code null} if they are. */
    static String algorithmProblem(XMLSignature signature) {
        SignedInfo info = signature.getSignedInfo();
        String method = info.getSignatureMethod().getAlgorithm();
        if (!SIGNATURE_METHODS.contains(method)) {
            return "signature algorithm " + method + " is not accepted";
        }
        String canonicalization = info.getCanonicalizationMethod().getAlgorithm();
        if (!CANONICALIZATIONS.contains(canonicalization)) {
            return "canonicalization " + canonicalization + " is not accepted";
        }
        for (Reference reference : info.getReferences()) {
            String digest = reference.getDigestMethod().getAlgorithm();
            if (!DIGEST_METHODS.contains(digest)) {
                return "digest algorithm " + digest + " is not accepted";
            }
            for (Object transform : reference.getTransforms()) {
                String algorithm = ((Transform) transform).getAlgorithm();
                if (!TRANSFORMS.contains(algorithm)) {
                    return "transform " + algorithm + " is not one SAML Core §5.4.4 allows";
                }
            }
        }
        return null;
    }

    /**
     * True iff {@code signature} validates against {@code key}: its {@code SignatureValue} and its
     * reference's digest. {@code signed}'s {@code ID} is the only identifier the reference can resolve
     * to, and the JDK's secure validation mode is on, so a second element carrying the same {@code ID}
     * fails rather than being chosen.
     */
    static boolean validate(Element signature, Element signed, PublicKey key) throws MarshalException {
        DOMValidateContext context = context(KeySelector.singletonKeySelector(key), signature, signed, true);
        XMLSignature parsed = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);
        try {
            return parsed.validate(context);
        } catch (XMLSignatureException wrongKeyOrMalformed) {
            return false;
        }
    }

    private static DOMValidateContext context(KeySelector keys, Element signature, Element signed,
                                              boolean secureValidation) {
        DOMValidateContext context = new DOMValidateContext(keys, signature);
        context.setIdAttributeNS(signed, null, "ID");
        context.setProperty("org.jcp.xml.dsig.secureValidation", secureValidation);
        context.setProperty("org.apache.jcp.xml.dsig.secureValidation", secureValidation);
        return context;
    }

    /** For reading a signature without validating it: there is no key to select. */
    private static final KeySelector NO_KEY = new KeySelector() {
        @Override
        public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method,
                                        XMLCryptoContext context) throws KeySelectorException {
            throw new KeySelectorException("not validating");
        }
    };
}
