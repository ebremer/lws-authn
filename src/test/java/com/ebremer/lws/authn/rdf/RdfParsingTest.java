/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.rdf;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.apache.jena.rdf.model.Model;
import org.junit.jupiter.api.Test;

import com.ebremer.lws.authn.ssicid.SsiCidConstants;
import com.ebremer.lws.authn.ssicid.verify.SelfSignedCidVerifier;

/**
 * P2-1. The verifiers used to pattern-match the JSON of a controlled identifier document — walking the
 * exact key names this project itself emits. That works against documents this provider serves and
 * fails against equally conforming documents from any other implementation, which is an
 * interoperability bug. These drive the real JSON-LD 1.1 processor instead.
 */
class RdfParsingTest {

    private static final String SUBJECT = "https://id.example/end-user";
    private static final String ISSUER = "https://openid.example";

    /** The shape every LWS OpenID suite example uses. */
    private static final String COMPACT_OPENID = """
            {"@context":["https://www.w3.org/ns/cid/v1"],
             "id":"https://id.example/end-user",
             "service":[{"id":"https://id.example/end-user#op",
                         "type":"https://www.w3.org/ns/lws#OpenIdProvider",
                         "serviceEndpoint":"https://openid.example"}]}""";

    private static boolean declaresProvider(Model model) {
        return model.contains(
                model.createResource(SUBJECT),
                model.createProperty("https://www.w3.org/ns/did#service"),
                (org.apache.jena.rdf.model.RDFNode) null);
    }

    @Test
    void parsesTheCompactShapeIntoTheExpectedTriples() {
        Model model = RdfParsing.parseJsonLd(COMPACT_OPENID, SUBJECT);
        assertTrue(declaresProvider(model), model.toString());
        assertTrue(model.contains(null,
                model.createProperty("https://www.w3.org/ns/did#serviceEndpoint"),
                model.createResource(ISSUER)), "serviceEndpoint is typed @id by the CID context");
    }

    /**
     * The point of using a processor rather than reading keys: an equally conforming document that
     * aliases terms, wraps itself in an {@code @graph} or names things differently still produces the
     * same triples. None of these would have been understood before.
     */
    @Test
    void parsesShapesThePatternMatcherWouldHaveMissed() {
        String aliased = """
                {"@context":["https://www.w3.org/ns/cid/v1",{"svc":"https://www.w3.org/ns/did#service"}],
                 "id":"https://id.example/end-user",
                 "svc":[{"@id":"https://id.example/end-user#op",
                         "@type":"https://www.w3.org/ns/lws#OpenIdProvider",
                         "serviceEndpoint":{"@id":"https://openid.example"}}]}""";
        assertTrue(declaresProvider(RdfParsing.parseJsonLd(aliased, SUBJECT)), "aliased term");

        String graph = """
                {"@context":["https://www.w3.org/ns/cid/v1"],
                 "@graph":[{"id":"https://id.example/end-user",
                            "service":[{"id":"https://id.example/end-user#op",
                                        "type":"https://www.w3.org/ns/lws#OpenIdProvider",
                                        "serviceEndpoint":"https://openid.example"}]}]}""";
        assertTrue(declaresProvider(RdfParsing.parseJsonLd(graph, SUBJECT)), "@graph wrapper");
    }

    /** The self-signed suite's document, read as RDF rather than as JSON keys. */
    @Test
    void parsesAVerificationMethodIncludingItsScopedPublicKeyJwk() {
        String cid = """
                {"@context":["https://www.w3.org/ns/cid/v1"],
                 "id":"https://id.example/end-user",
                 "authentication":[{"id":"https://id.example/end-user#k1",
                                    "type":"JsonWebKey",
                                    "controller":"https://id.example/end-user",
                                    "publicKeyJwk":{"kid":"k1","kty":"EC","crv":"P-256","x":"X","y":"Y"}}]}""";
        Model model = RdfParsing.parseJsonLd(cid, SUBJECT);

        // publicKeyJwk is defined only inside the JsonWebKey type-scoped context, so this also proves
        // scoped contexts are being applied rather than guessed at.
        List<SelfSignedCidVerifier.VerificationMethod> methods =
                SelfSignedCidVerifier.collectFromRdf(model, SUBJECT);
        assertEquals(1, methods.size(), model.toString());
        assertEquals("k1", methods.get(0).publicKeyJwk().path("kid").asText());
        assertEquals(SUBJECT + "#k1", methods.get(0).id());
        assertTrue(model.contains(model.createResource(SUBJECT),
                model.createProperty(SsiCidConstants.SEC_AUTHENTICATION), (org.apache.jena.rdf.model.RDFNode) null));
    }

    /**
     * Contexts come from the JAR. A JSON-LD processor left to itself fetches every {@code @context}
     * URL a document names — an unvetted outbound request during verification, and a dependency on
     * w3.org being reachable for anything to verify at all.
     */
    @Test
    void refusesToFetchAnUnbundledContext() {
        String remote = """
                {"@context":"https://attacker.example/context.jsonld","id":"https://id.example/end-user"}""";
        assertThrows(RuntimeException.class, () -> RdfParsing.parseJsonLd(remote, SUBJECT),
                "a context this provider does not bundle must fail the parse, not be fetched");
        assertTrue(LocalJsonLdContexts.bundledContexts().contains("https://www.w3.org/ns/cid/v1"));
    }

    /** parse() falls back to null for JSON-LD it cannot process, so the caller can try the old reader. */
    @Test
    void parseReportsUnprocessableJsonLdRatherThanThrowing() {
        assertNull(RdfParsing.parse("{\"@context\":\"https://attacker.example/c\"}", "application/ld+json", SUBJECT));
        assertNull(RdfParsing.parse("{not json at all", "application/ld+json", SUBJECT));
        assertNotNull(RdfParsing.parse(COMPACT_OPENID, "application/ld+json", SUBJECT));
    }

    /**
     * P3-5. An unrecognised content type used to fall through to the Turtle parser, so an HTML error
     * page came back as "Turtle syntax error at line 1" — misleading about what actually went wrong.
     */
    @Test
    void refusesAContentTypeThatIsNotAnRdfSyntax() {
        String html = "<html><body>404 Not Found</body></html>";
        RdfParsing.UnsupportedSyntaxException e = assertThrows(RdfParsing.UnsupportedSyntaxException.class,
                () -> RdfParsing.parse(html, "text/html; charset=utf-8", SUBJECT));
        assertEquals("text/html", e.getContentType(), "the media type is reported bare and lower-cased");

        assertThrows(RdfParsing.UnsupportedSyntaxException.class,
                () -> RdfParsing.parse("%PDF-1.7", "application/pdf", SUBJECT));
    }

    /**
     * The brace-sniff is a fallback for a document that declares nothing, and must not rescue one that
     * declares the wrong thing: an HTML body starting with a brace is still not JSON-LD.
     */
    @Test
    void theJsonSniffDoesNotOverrideADeclaredContentType() {
        assertThrows(RdfParsing.UnsupportedSyntaxException.class,
                () -> RdfParsing.parse("{\"error\":\"not found\"}", "text/html", SUBJECT));
    }

    /** A document that declares no content type at all is still read as Turtle, the syntax we ask for. */
    @Test
    void anAbsentContentTypeStillFallsBackToTurtle() {
        Model model = RdfParsing.parse(
                "<" + SUBJECT + "> <https://www.w3.org/ns/did#service> <" + SUBJECT + "#op> .",
                null, SUBJECT);
        assertTrue(declaresProvider(model));
        assertNotNull(RdfParsing.parse(COMPACT_OPENID, null, SUBJECT), "and JSON-LD is still sniffed");
    }

    @Test
    void stillParsesTheOtherSyntaxes()  {
        Model turtle = RdfParsing.parse(
                "<" + SUBJECT + "> <https://www.w3.org/ns/did#service> <" + SUBJECT + "#op> .",
                "text/turtle", SUBJECT);
        assertTrue(declaresProvider(turtle));
    }

    /**
     * R-04. Only the syntaxes the verifiers ask for are read. Jena reads many more, and one of them —
     * the binary RDF-Thrift encoding — turned these eight bytes into a 95 MB allocation and an empty
     * graph, without an error.
     */
    @Test
    void refusesRdfSyntaxesNobodyAskedFor() {
        String thrift = new String(new byte[]{0x1C, 0x18, (byte) 0xE5, (byte) 0x80, (byte) 0x80, 0x2D},
                java.nio.charset.StandardCharsets.UTF_8);
        RdfParsing.UnsupportedSyntaxException refused = assertThrows(RdfParsing.UnsupportedSyntaxException.class,
                () -> RdfParsing.parse(thrift, "application/rdf+thrift", SUBJECT));
        assertEquals("application/rdf+thrift", refused.getContentType());
        for (String other : new String[]{"application/rdf+protobuf", "application/trig", "text/n3",
                "application/n-quads", "application/trix+xml", "application/rdf+json", "text/plain"}) {
            assertThrows(RdfParsing.UnsupportedSyntaxException.class,
                    () -> RdfParsing.parse("<" + SUBJECT + "> <" + SUBJECT + "#p> <" + SUBJECT + "#o> .", other, SUBJECT),
                    other);
        }
    }

    /** The syntaxes the verifiers do ask for are all still read, by their registered media types. */
    @Test
    void readsEverySyntaxTheVerifiersAskFor() {
        String triple = "<" + SUBJECT + "> <https://www.w3.org/ns/did#service> <" + SUBJECT + "#op> .";
        assertTrue(declaresProvider(RdfParsing.parse(triple, "text/turtle; charset=utf-8", SUBJECT)));
        assertTrue(declaresProvider(RdfParsing.parse(triple, "application/n-triples", SUBJECT)));
        String rdfXml = "<rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\" "
                + "xmlns:did=\"https://www.w3.org/ns/did#\"><rdf:Description rdf:about=\"" + SUBJECT + "\">"
                + "<did:service rdf:resource=\"" + SUBJECT + "#op\"/></rdf:Description></rdf:RDF>";
        assertTrue(declaresProvider(RdfParsing.parse(rdfXml, "application/rdf+xml", SUBJECT)));
        assertNotNull(RdfParsing.parse(COMPACT_OPENID, "application/json", SUBJECT));
    }

    /**
     * R-09. Jena's Turtle parser recurses once per blank node or collection: 5 000 levels — 120 KB, under
     * the response cap — overflowed the stack, and the error escaped every handler as a 500.
     */
    @Test
    void refusesTurtleNestedTooDeep() {
        String bnodes = "<" + SUBJECT + "> <" + SUBJECT + "#p> " + ("[<" + SUBJECT + "#p> ").repeat(5_000)
                + "1" + "]".repeat(5_000) + " .";
        assertThrows(RdfParsing.TooDeeplyNestedException.class, () -> RdfParsing.parse(bnodes, "text/turtle", SUBJECT));
        String lists = "<" + SUBJECT + "> <" + SUBJECT + "#p> " + "(".repeat(5_000) + ")".repeat(5_000) + " .";
        assertThrows(RdfParsing.TooDeeplyNestedException.class, () -> RdfParsing.parse(lists, null, SUBJECT),
                "undeclared, and so read as Turtle");
    }

    /** R-09. The JSON-LD processor recurses per nested context: 500 of them overflowed. */
    @Test
    void refusesJsonLdNestedTooDeep() {
        String contexts = "{\"@context\":{\"p\":\"" + SUBJECT + "#p\"},\"@id\":\"" + SUBJECT + "\",\"p\":"
                + ("{\"@context\":{\"q\":\"" + SUBJECT + "#q\"},\"q\":").repeat(500) + "1" + "}".repeat(500) + "}";
        assertThrows(RdfParsing.TooDeeplyNestedException.class,
                () -> RdfParsing.parse(contexts, "application/ld+json", SUBJECT),
                "refused, not handed to the compact reader as a shape it might understand");
        String arrays = "{\"@id\":\"" + SUBJECT + "\",\"x\":" + "[".repeat(100) + "]".repeat(100) + "}";
        assertThrows(RdfParsing.TooDeeplyNestedException.class, () -> RdfParsing.parse(arrays, "application/json", SUBJECT));
    }

    /** Up to the limit is fine; brackets inside strings, IRIs and comments are not nesting. */
    @Test
    void countsOnlyStructuralNesting() {
        int depth = RdfParsing.MAX_NESTING_DEPTH;
        String deepEnough = "<" + SUBJECT + "> <" + SUBJECT + "#p> " + ("[<" + SUBJECT + "#p> ").repeat(depth) + "1"
                + "]".repeat(depth) + " .";
        assertEquals(depth + 1, RdfParsing.parse(deepEnough, "text/turtle", SUBJECT).size());

        String brackets = "[(".repeat(100);
        String turtle = "# " + brackets + "\n"
                + "<" + SUBJECT + "> <" + SUBJECT + "#p> \"" + brackets + "\\\"" + brackets + "\" ;\n"
                + "  <" + SUBJECT + "#q> '" + brackets + "' ;\n"
                + "  <" + SUBJECT + "#r> \"\"\"" + brackets + "\" \"\" " + brackets + "\"\"\" ;\n"
                + "  <" + SUBJECT + "#s> '''" + brackets + "' '' " + brackets + "''' ;\n"
                + "  <" + SUBJECT + "#t> <" + SUBJECT + "#" + "[".repeat(100) + "> .";
        assertEquals(5, assertDoesNotThrow(() -> RdfParsing.parse(turtle, "text/turtle", SUBJECT)).size());

        String json = "{\"@context\":{\"p\":\"" + SUBJECT + "#p\"},\"@id\":\"" + SUBJECT + "\","
                + "\"p\":\"" + "{[".repeat(100) + "\\\"" + "{[".repeat(100) + "\"}";
        assertEquals(1, assertDoesNotThrow(() -> RdfParsing.parse(json, "application/ld+json", SUBJECT)).size());
    }

    /** R-19. CID 1.0 Appendix A's media type is JSON-LD in the CID context, and is read as that. */
    @Test
    void readsApplicationCidAsJsonLd() {
        assertDoesNotThrow(() -> RdfParsing.requireSupported("application/cid; charset=utf-8"));
        assertTrue(RdfParsing.isJsonLd("application/cid", COMPACT_OPENID));
        assertTrue(declaresProvider(RdfParsing.parse(COMPACT_OPENID, "application/cid", SUBJECT)));
    }

    /**
     * R-19. CID 1.0 §4.2.1: a consumer "MUST inject or append an {@code @context}" when a document has
     * none. Without it every term was undefined and the graph came out empty.
     */
    @Test
    void readsADocumentWithoutAContextInTheCidContext() {
        String contextless = COMPACT_OPENID.replace("\"@context\":[\"https://www.w3.org/ns/cid/v1\"],", "");
        assertFalse(contextless.contains("@context"));
        assertTrue(declaresProvider(RdfParsing.parse(contextless, "application/ld+json", SUBJECT)));
        assertTrue(declaresProvider(RdfParsing.parse(contextless, "application/json", SUBJECT)));
        // a context of its own is left alone: here, one that defines nothing the document uses
        String own = COMPACT_OPENID.replace("[\"https://www.w3.org/ns/cid/v1\"]", "{\"x\":\"https://x.example/\"}");
        assertFalse(declaresProvider(RdfParsing.parse(own, "application/ld+json", SUBJECT)));
    }

    /** Everything the verifiers ask for is something they read. */
    @Test
    void everyTypeTheVerifiersAcceptIsOneTheyRead() {
        for (String range : RdfParsing.ACCEPT.split(",")) {
            String type = range.split(";")[0].trim();
            assertDoesNotThrow(() -> RdfParsing.requireSupported(type), type);
        }
        assertTrue(RdfParsing.ACCEPT.contains("application/cid"));
        assertTrue(RdfParsing.ACCEPT.contains("application/json"));
    }

    /** R-18. The topmost map's id, resolved against the document's URL. */
    @Test
    void readsTheTopmostId() throws Exception {
        assertEquals(SUBJECT, RdfParsing.topmostId(COMPACT_OPENID, SUBJECT));
        assertEquals(SUBJECT, RdfParsing.topmostId("{\"@id\":\"" + SUBJECT + "\"}", SUBJECT));
        assertEquals(SUBJECT, RdfParsing.topmostId("{\"id\":\"end-user\"}", SUBJECT), "a relative id resolves");
        assertNull(RdfParsing.topmostId("{\"id\":\"\"}", SUBJECT), "an empty id names nothing");
        assertEquals(SUBJECT + "#me", RdfParsing.topmostId("{\"id\":\"#me\"}", SUBJECT));
        assertEquals("https://other.example/doc", RdfParsing.topmostId(
                "{\"id\":\"https://other.example/doc\",\"alsoKnownAs\":[{\"id\":\"" + SUBJECT + "\"}]}", SUBJECT));
        assertNull(RdfParsing.topmostId("{\"@graph\":[{\"id\":\"" + SUBJECT + "\"}]}", SUBJECT), "no topmost id");
        assertNull(RdfParsing.topmostId("[{\"id\":\"" + SUBJECT + "\"}]", SUBJECT), "no topmost map");
        assertNull(RdfParsing.topmostId("{\"id\":[\"" + SUBJECT + "\"]}", SUBJECT), "not one string");
        assertThrows(java.io.IOException.class, () -> RdfParsing.topmostId("not json", SUBJECT));
    }
}
