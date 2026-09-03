/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * The JSON bodies these endpoints return for anything that is not a verification result: errors,
 * refusals, and the "not found" of a controlled identifier document.
 */
package com.ebremer.lws.authn.http;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.util.JsonSerialization;

/**
 * Builds the small JSON responses this extension returns, through a serializer rather than by
 * concatenating strings.
 *
 * <p>Every one of these bodies used to be written as a string literal with a message interpolated into
 * it. Nothing was broken by that — every caller passed a constant — but it is one edit from a message
 * containing a quote or a backslash and emitting JSON no client can parse, and the fix is not a rule to
 * remember, it is a function that cannot be called wrongly.</p>
 *
 * <p>The shape is uniform across every endpoint and every status: an {@code error} code and an
 * {@code error_description}, matching the OAuth 2.0 error response the {@code verify} endpoints'
 * callers already handle. A caller can therefore read a failure the same way whichever endpoint and
 * whichever status produced it.</p>
 *
 * @author Erich Bremer
 */
public final class JsonResponses {

    private static final Logger log = Logger.getLogger(JsonResponses.class);

    private JsonResponses() {
    }

    /**
     * Serializes {@code body} as JSON.
     *
     * <p>Falls back to a fixed, valid JSON literal if serialization somehow fails: this is used on
     * error paths, where the caller has no better response to send and swallowing the original status
     * would be worse than a generic body.</p>
     */
    public static String json(Object body) {
        try {
            return JsonSerialization.writeValueAsPrettyString(body);
        } catch (IOException e) {
            log.warn("Could not serialize an lws-authn response body", e);
            return "{\"error\":\"server_error\"}";
        }
    }

    /** A response of {@code status} whose body is {@code body} serialized as JSON. */
    public static Response of(Response.Status status, Object body) {
        return Response.status(status).entity(json(body)).type(MediaType.APPLICATION_JSON).build();
    }

    /** An {@code {"error": …, "error_description": …}} response. */
    public static Response error(Response.Status status, String code, String description) {
        return of(status, errorBody(code, description));
    }

    /** The body of {@link #error}, for a caller that needs to add headers of its own. */
    public static Map<String, Object> errorBody(String code, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code);
        if (description != null) {
            body.put("error_description", description);
        }
        return body;
    }

    /** {@code 400} — the request itself is malformed, independently of any credential in it. */
    public static Response badRequest(String description) {
        return error(Response.Status.BAD_REQUEST, "invalid_request", description);
    }

    /**
     * {@code 406} naming the syntaxes on offer, rather than silently serving one that was not asked
     * for.
     *
     * <p>Carries a body deliberately: Keycloak's {@code DefaultSecurityHeadersProvider} logs
     * "MediaType not set" and turns any response without a content type into a 500, so an empty 406
     * never reaches the client as a 406.</p>
     */
    public static Response notAcceptable(List<String> supported) {
        Map<String, Object> body = errorBody("not_acceptable",
                "none of the syntaxes this endpoint serves is acceptable to the client");
        body.put("supported", supported);
        return Response.status(Response.Status.NOT_ACCEPTABLE)
                .entity(json(body))
                .type(MediaType.APPLICATION_JSON)
                .header("Vary", "Accept")
                .build();
    }

    /** {@code 404}, typed for the same reason as the 406 above. */
    public static Response notFound(String description) {
        return error(Response.Status.NOT_FOUND, "not_found", description);
    }

    /**
     * What an endpoint answers when its suite is switched off for this realm.
     *
     * <p>A 404 rather than a 403: a suite this deployment does not offer has no endpoint there, which
     * is exactly what a 404 says, and it does not advertise that the extension is installed but
     * disabled.</p>
     */
    public static Response notEnabled() {
        return notFound("this endpoint is not enabled on this realm");
    }
}
