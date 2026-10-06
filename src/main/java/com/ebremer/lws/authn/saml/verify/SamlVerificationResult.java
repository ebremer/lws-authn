/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Result of validating a signed SAML 2.0 assertion as an LWS authentication credential.
 */
package com.ebremer.lws.authn.saml.verify;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * JSON-serializable outcome of {@link SamlCredentialVerifier}.
 *
 * @author Erich Bremer
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"valid", "subject", "subjectFormat", "issuer", "client", "audiences", "recipient", "tokenType", "notBefore", "notOnOrAfter", "oneTimeUse", "trustSource", "identityProvider", "certificateSha256", "checks", "errors", "traceId"})
public class SamlVerificationResult {

    private boolean valid;
    private String subject;
    private String subjectFormat;
    private String issuer;
    private String recipient;
    private String notBefore;
    private String notOnOrAfter;
    private Boolean oneTimeUse;
    private String trustSource;
    private String identityProvider;
    private String certificateSha256;
    private List<String> audiences = new ArrayList<>();
    private final Map<String, Boolean> checks = new LinkedHashMap<>();
    private final List<String> errors = new ArrayList<>();
    private String traceId;
    private String client;
    private String tokenType;

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    /** The {@code <NameID>}'s {@code Format}, or {@code null} if it names none (R-20). */
    public String getSubjectFormat() {
        return subjectFormat;
    }

    public void setSubjectFormat(String subjectFormat) {
        this.subjectFormat = subjectFormat;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getRecipient() {
        return recipient;
    }

    public void setRecipient(String recipient) {
        this.recipient = recipient;
    }

    public String getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    public String getNotOnOrAfter() {
        return notOnOrAfter;
    }

    public void setNotOnOrAfter(String notOnOrAfter) {
        this.notOnOrAfter = notOnOrAfter;
    }

    /**
     * {@code true} when the assertion carries {@code <OneTimeUse>}, otherwise absent. SAML Core §2.5.1.5:
     * such an assertion "SHOULD be used immediately by the relying party and MUST NOT be retained for
     * future use". This verifier retains nothing; a caller that caches verdicts must not cache this one
     * (R-21).
     */
    public Boolean getOneTimeUse() {
        return oneTimeUse;
    }

    public void setOneTimeUse(Boolean oneTimeUse) {
        this.oneTimeUse = oneTimeUse;
    }

    /**
     * Where the certificate that verified the credential came from: {@code request}, the caller's
     * {@code certificate} parameter, or {@code identity-provider}, one of the realm's SAML identity
     * providers whose entity ID is the assertion's issuer (R-25). Absent when nothing verified.
     */
    public String getTrustSource() {
        return trustSource;
    }

    public void setTrustSource(String trustSource) {
        this.trustSource = trustSource;
    }

    /** The alias of the identity provider whose certificate verified the credential, if one did. */
    public String getIdentityProvider() {
        return identityProvider;
    }

    public void setIdentityProvider(String identityProvider) {
        this.identityProvider = identityProvider;
    }

    /**
     * The SHA-256 fingerprint of the certificate that verified the credential, as
     * {@code openssl x509 -noout -fingerprint -sha256} prints it. A caller that supplies several
     * certificates in turn learns which one it was; with a caller-supplied certificate, {@code valid}
     * says only that this certificate signed the credential, and the caller decides what that is worth.
     */
    public String getCertificateSha256() {
        return certificateSha256;
    }

    public void setCertificateSha256(String certificateSha256) {
        this.certificateSha256 = certificateSha256;
    }

    public List<String> getAudiences() {
        return audiences;
    }

    public void setAudiences(List<String> audiences) {
        this.audiences = audiences;
    }

    public Map<String, Boolean> getChecks() {
        return checks;
    }

    public List<String> getErrors() {
        return errors;
    }

    /**
     * The LWS client identifier the credential names. LWS core §4.1 makes the client a REQUIRED claim
     * of every authentication credential, so a valid result always carries one: {@code azp} for
     * OpenID, {@code client_id} for the self-issued suites, and the {@code Recipient} of the bearer
     * {@code <SubjectConfirmationData>} for SAML.
     */
    public String getClient() {
        return client;
    }

    public void setClient(String client) {
        this.client = client;
    }

    /**
     * The token type URI this suite is associated with (LWS core §4.3), reported so a caller can feed
     * the credential straight into an RFC 8693 token exchange.
     */
    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    /**
     * Correlation id for the server log. Failure detail that would describe this server's network is
     * logged rather than returned; this id ties the two together.
     */
    public String getTraceId() {
        return traceId;
    }

    public void setTraceId(String traceId) {
        this.traceId = traceId;
    }

    public void check(String name, boolean ok) {
        checks.put(name, ok);
    }

    public void error(String message) {
        errors.add(message);
    }

    /** Marks the credential invalid and returns this result (convenience for early returns). */
    public SamlVerificationResult fail() {
        this.valid = false;
        return this;
    }
}
