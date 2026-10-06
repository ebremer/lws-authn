/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.openid.cid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.riot.RDFFormat;
import org.apache.jena.vocabulary.RDF;
import org.junit.jupiter.api.Test;

import com.ebremer.lws.authn.openid.LWSConstants;
import com.ebremer.lws.authn.rdf.RdfParsing;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * R-44. The controlled identifier document the OpenID suite's {@code lws/cid/{userId}} endpoint serves:
 * the suite's own shape, and the same graph in every syntax it is served in — the JSON-LD is written by
 * hand rather than by Jena, so nothing else holds it to the model.
 */
class ControlledIdentifierDocumentTest {

    private static final String WEBID = "https://idp.example/realms/demo/lws/cid/2b8a5c1e-0f4d-4c7e-9a3b-6d1f0e2c4b7a";
    private static final String ISSUER = "https://idp.example/realms/demo";
    private static final ControlledIdentifierDocument DOCUMENT = new ControlledIdentifierDocument(WEBID, ISSUER);

    /**
     * The suite: the subject's document "MUST include a service entry with type
     * {@code https://www.w3.org/ns/lws#OpenIdProvider}" whose {@code serviceEndpoint} is the issuer. One
     * service, named, typed and pointing there, and nothing else about the subject.
     */
    @Test
    void declaresOneOpenIdProviderServiceForTheSubject() {
        Model model = DOCUMENT.toModel();
        Resource subject = model.createResource(WEBID);
        List<Statement> services = model.listStatements(subject, model.createProperty(LWSConstants.DID_SERVICE),
                (org.apache.jena.rdf.model.RDFNode) null).toList();
        assertEquals(1, services.size(), String.valueOf(services));
        Resource service = services.get(0).getResource();
        assertEquals(WEBID + "#openid-provider", service.getURI(), "named, so it can be referred to");
        assertTrue(service.hasProperty(RDF.type, model.createResource(LWSConstants.OPENID_PROVIDER_TYPE)));
        assertEquals(ISSUER, service.getPropertyResourceValue(
                model.createProperty(LWSConstants.DID_SERVICE_ENDPOINT)).getURI());
        assertEquals(3, model.size(), "subject→service, and the service's type and endpoint: " + model);
    }

    /**
     * CID 1.0 §2: "A controlled identifier document MUST contain an {@code id} value in the topmost map",
     * which the suite requires to equal the subject — exactly, as the verifier compares it.
     */
    @Test
    void theJsonLdHasTheSuitesShape() throws Exception {
        JsonNode json = new ObjectMapper().readTree(DOCUMENT.toJsonLd());
        assertEquals(LWSConstants.CID_CONTEXT, json.path("@context").path(0).asText());
        assertEquals(1, json.path("@context").size());
        assertEquals(WEBID, json.path("id").asText());
        assertEquals(WEBID, RdfParsing.topmostId(DOCUMENT.toJsonLd(), WEBID));
        assertEquals(1, json.path("service").size());
        JsonNode service = json.path("service").path(0);
        assertEquals(WEBID + "#openid-provider", service.path("id").asText());
        assertEquals(LWSConstants.OPENID_PROVIDER_TYPE, service.path("type").asText());
        assertEquals(ISSUER, service.path("serviceEndpoint").asText());
    }

    /**
     * The hand-written JSON-LD, read by the JSON-LD processor with the CID context, is the model — so the
     * {@code serviceEndpoint} it writes as a string is the IRI the model says, not a literal.
     */
    @Test
    void theJsonLdMeansWhatTheModelSays() {
        Model parsed = RdfParsing.parse(DOCUMENT.toJsonLd(), LWSConstants.JSON_LD, WEBID);
        assertTrue(parsed != null && parsed.isIsomorphicWith(DOCUMENT.toModel()),
                () -> "parsed: " + parsed + "\nmodel: " + DOCUMENT.toModel());
    }

    /** Every RDF syntax the endpoint negotiates reads back as the same graph. */
    @Test
    void everyRdfSyntaxReadsBackAsTheModel() {
        Object[][] syntaxes = {
                {RDFFormat.TURTLE, LWSConstants.TURTLE},
                {RDFFormat.NTRIPLES, LWSConstants.N_TRIPLES},
                {RDFFormat.RDFXML, LWSConstants.RDF_XML},
        };
        for (Object[] syntax : syntaxes) {
            String body = DOCUMENT.toRdf((RDFFormat) syntax[0]);
            Model parsed = RdfParsing.parse(body, (String) syntax[1], WEBID);
            assertTrue(parsed.isIsomorphicWith(DOCUMENT.toModel()), syntax[1] + ":\n" + body);
        }
    }

    /** Two subjects of one issuer get two documents, each naming its own service. */
    @Test
    void eachSubjectsServiceIsItsOwn() {
        Model other = new ControlledIdentifierDocument(WEBID + "x", ISSUER).toModel();
        assertTrue(other.containsResource(other.createResource(WEBID + "x#openid-provider")));
        assertTrue(!other.containsResource(other.createResource(WEBID + "#openid-provider")));
    }
}
