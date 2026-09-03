/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.rdf.RdfContentNegotiation;

/**
 * P3-2. These bodies used to be string literals with a message interpolated into them. Every caller
 * passed a constant, so nothing was broken — but it was one edit from emitting JSON no client can
 * parse, and a serializer cannot be called wrongly.
 */
class JsonResponsesTest {

    private static JsonNode body(Response response) throws Exception {
        return JsonSerialization.mapper.readTree((String) response.getEntity());
    }

    @Test
    void aMessageWithQuotesAndBackslashesStillProducesParseableJson() throws Exception {
        String nasty = "missing \"credential\" \\ or a newline\nand a tab\there";
        JsonNode json = body(JsonResponses.badRequest(nasty));
        assertEquals("invalid_request", json.get("error").asText());
        assertEquals(nasty, json.get("error_description").asText(), "the message survives the round trip");
    }

    @Test
    void everyErrorHasTheSameShape() throws Exception {
        for (Response response : new Response[]{
                JsonResponses.badRequest("bad"),
                JsonResponses.notFound("gone"),
                JsonResponses.notEnabled(),
                JsonResponses.error(Response.Status.TOO_MANY_REQUESTS, "slow_down", "later"),
                JsonResponses.notAcceptable(RdfContentNegotiation.SUPPORTED)}) {
            assertEquals(MediaType.APPLICATION_JSON, response.getMediaType().toString(),
                    "an untyped response becomes a 500 in Keycloak, whatever status it carried");
            JsonNode json = body(response);
            assertTrue(json.hasNonNull("error"), json.toString());
            assertTrue(json.hasNonNull("error_description"), json.toString());
        }
    }

    @Test
    void statusesAreWhatTheyClaimToBe() {
        assertEquals(400, JsonResponses.badRequest("bad").getStatus());
        assertEquals(404, JsonResponses.notFound("gone").getStatus());
        assertEquals(404, JsonResponses.notEnabled().getStatus(),
                "a suite that is switched off has no endpoint there, rather than a forbidden one");
        assertEquals(406, JsonResponses.notAcceptable(RdfContentNegotiation.SUPPORTED).getStatus());
    }

    @Test
    void notAcceptableNamesTheSyntaxesOnOfferAndVariesOnAccept() throws Exception {
        Response response = JsonResponses.notAcceptable(RdfContentNegotiation.SUPPORTED);
        assertEquals("Accept", response.getHeaderString("Vary"));
        JsonNode supported = body(response).get("supported");
        assertEquals(RdfContentNegotiation.SUPPORTED.size(), supported.size());
        assertEquals(RdfContentNegotiation.JSON_LD, supported.get(0).asText());
    }

    @Test
    void anArbitraryBodySerializesThroughTheSameSerializer() throws Exception {
        Response response = JsonResponses.of(Response.Status.OK,
                JsonResponses.errorBody("code", "description"));
        assertEquals(200, response.getStatus());
        assertEquals("code", body(response).get("error").asText());
    }
}
