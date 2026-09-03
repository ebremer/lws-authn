/*
 * Copyright Erich Bremer.
 *
 * Result of validating an ID Token as an LWS authentication credential.
 */
package com.ebremer.lws.authn.openid.verify;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * JSON-serializable outcome of {@link LWSCredentialVerifier}. {@code checks} records each step of the
 * validation algorithm; {@code errors} lists the reasons a credential was rejected.
 *
 * @author Erich Bremer
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"valid", "subject", "issuer", "checks", "errors", "traceId"})
public class VerificationResult {

    private boolean valid;
    private String subject;
    private String issuer;
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

    /** Records the outcome of a single validation step. */
    public void check(String name, boolean ok) {
        checks.put(name, ok);
    }

    /** Records a rejection reason. */
    public void error(String message) {
        errors.add(message);
    }

    /** Marks the credential invalid and returns this result (convenience for early returns). */
    public VerificationResult fail() {
        this.valid = false;
        return this;
    }
}
