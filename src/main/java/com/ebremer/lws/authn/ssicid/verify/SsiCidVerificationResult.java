/*
 * Copyright Erich Bremer.
 *
 * Result of validating a self-issued JWT as an LWS authentication credential (self-signed CID suite).
 */
package com.ebremer.lws.authn.ssicid.verify;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

/**
 * JSON-serializable outcome of {@link SelfSignedCidVerifier}.
 *
 * @author Erich Bremer
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"valid", "subject", "checks", "errors", "traceId"})
public class SsiCidVerificationResult {

    private boolean valid;
    private String subject;
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
    public SsiCidVerificationResult fail() {
        this.valid = false;
        return this;
    }
}
