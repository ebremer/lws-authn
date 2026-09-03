package com.ebremer.lws.authn.rdf;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
}
