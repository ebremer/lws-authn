/*
 * Copyright Erich Bremer.
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
@JsonPropertyOrder({"valid", "subject", "issuer", "audiences", "recipient", "notBefore", "notOnOrAfter", "checks", "errors", "traceId"})
public class SamlVerificationResult {

    private boolean valid;
    private String subject;
    private String issuer;
    private String recipient;
    private String notBefore;
    private String notOnOrAfter;
    private List<String> audiences = new ArrayList<>();
    private final Map<String, Boolean> checks = new LinkedHashMap<>();
    private final List<String> errors = new ArrayList<>();
    private String traceId;

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
