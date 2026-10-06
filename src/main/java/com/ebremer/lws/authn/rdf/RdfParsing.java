/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Content-type detection and parsing for the (arbitrary-syntax) controlled identifier documents the
 * OpenID and self-signed CID verifiers dereference. Shared by both verifiers so the syntax handling
 * stays identical.
 */
package com.ebremer.lws.authn.rdf;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;

import com.apicatalog.jsonld.JsonLdOptions;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.riot.RDFParser;
import org.apache.jena.riot.system.jsonld.TitaniumJsonLdOptions;
import org.apache.jena.sparql.util.Context;

/**
 * RDF syntax helpers for controlled identifier documents.
 *
 * @author Erich Bremer
 */
public final class RdfParsing {

    private RdfParsing() {
    }

    private static final String JSON_LD = "application/ld+json";

    /**
     * The non-JSON syntaxes a dereferenced document may be read as: exactly the ones the verifiers ask
     * for in {@code Accept}, alongside JSON-LD.
     *
     * <p>Not "whatever Jena can read". That used to be the test, and Jena reads a great deal — TriG, N3,
     * TriX, RDF/JSON, and the binary RDF-Thrift and RDF-Protobuf encodings. A subject served as
     * {@code application/rdf+thrift} with the eight-byte body {@code 1C 18 E5 80 80 2D} made the Thrift
     * reader allocate 95&nbsp;MB for a string length it was told to expect and return an empty graph
     * without complaint; enough of those at once and the server ran out of memory (R-04). A document in
     * a syntax nobody asked for is not one the verifier needs to read.</p>
     */
    private static final Map<String, Lang> READABLE = Map.of(
            "text/turtle", Lang.TURTLE,
            "application/n-triples", Lang.NTRIPLES,
            "application/rdf+xml", Lang.RDFXML);

    /**
     * Thrown when a dereferenced document declares a content type that is not an RDF syntax this
     * verifier reads.
     *
     * <p>The alternative — what this class used to do — was to hand the bytes to the Turtle parser and
     * see what happened. It failed closed, so nothing was insecure about it, but an HTML error page,
     * a PDF or a plain-text 404 body all came back as a Turtle syntax error somewhere in line 1, which
     * says nothing about the actual problem: the server at the subject's URL did not serve a
     * controlled identifier document. Naming the content type says exactly that.</p>
     */
    public static final class UnsupportedSyntaxException extends RuntimeException {
        private final String contentType;

        UnsupportedSyntaxException(String contentType) {
            super("not an RDF syntax this verifier reads: " + contentType);
            this.contentType = contentType;
        }

        /** The offending media type, already reduced to its bare {@code type/subtype}. */
        public String getContentType() {
            return contentType;
        }
    }

    /**
     * How deep a dereferenced document may nest: blank nodes and collections in Turtle, objects and
     * arrays in JSON-LD. A controlled identifier document nests a handful of levels.
     *
     * <p>Jena's Turtle parser and the JSON-LD processor recurse once per level, and nothing bounded
     * that: five thousand levels of Turtle {@code [ … ]} — 120&nbsp;KB, under the response cap — and five
     * hundred nested JSON-LD {@code @context}s overflowed the stack before any signature was checked,
     * and the {@link StackOverflowError} escaped every handler as a {@code 500} (R-09). RDF/XML is read
     * without recursion, and N-Triples cannot nest.</p>
     */
    public static final int MAX_NESTING_DEPTH = 64;

    /** Thrown when a dereferenced document nests deeper than {@link #MAX_NESTING_DEPTH}. */
    public static final class TooDeeplyNestedException extends RuntimeException {
        TooDeeplyNestedException() {
            super("the document nests deeper than " + MAX_NESTING_DEPTH + " levels");
        }
    }

    /** The bare {@code type/subtype} of a {@code Content-Type}, lower-cased; {@code null} if absent. */
    private static String mediaType(String contentType) {
        if (contentType == null) {
            return null;
        }
        String bare = contentType.split(";")[0].trim().toLowerCase(Locale.ROOT);
        return bare.isEmpty() ? null : bare;
    }

    /**
     * Throws unless {@code contentType} is absent or names a syntax this class can read.
     *
     * @throws UnsupportedSyntaxException if it names something else
     */
    public static void requireSupported(String contentType) {
        String ct = mediaType(contentType);
        if (ct == null || ct.equals(JSON_LD) || ct.equals("application/json")) {
            return;
        }
        if (!READABLE.containsKey(ct)) {
            throw new UnsupportedSyntaxException(ct);
        }
    }

    /**
     * Decides whether a dereferenced document should be read as JSON-LD: by content type when one is
     * present and recognised, otherwise by sniffing a leading {@code {} / {@code [}.
     */
    public static boolean isJsonLd(String contentType, String body) {
        String ct = mediaType(contentType);
        if (ct != null) {
            if (ct.equals(JSON_LD) || ct.equals("application/json")) {
                return true;
            }
            if (READABLE.containsKey(ct)) {
                return false; // one of the non-JSON syntaxes the verifiers ask for
            }
        }
        String trimmed = body == null ? "" : body.trim();
        return trimmed.startsWith("{") || trimmed.startsWith("[");
    }

    /**
     * Parses Turtle / N-Triples / RDF/XML with Jena RIOT.
     *
     * <p>A document that declares any other content type — including another RDF syntax Jena could
     * read, see {@link #READABLE} — is <strong>refused</strong>, not guessed at. Only a document that declares nothing at all falls back to Turtle: that is the
     * syntax the verifiers ask for first and the WebID/Solid norm, so it is the best guess available
     * when the server offers none, and it is a guess about silence rather than a contradiction of
     * something the server actually said.</p>
     *
     * @throws UnsupportedSyntaxException if {@code contentType} names something that is not an RDF
     *                                    syntax this verifier reads
     */
    public static Model parseRdf(String body, String contentType, String base) {
        Lang lang = Lang.TURTLE;
        String ct = mediaType(contentType);
        if (ct != null) {
            lang = READABLE.get(ct);
            if (lang == null) {
                throw new UnsupportedSyntaxException(ct);
            }
        }
        if (lang == Lang.TURTLE) {
            requireShallow(body, false);
        }
        Model model = ModelFactory.createDefaultModel();
        try {
            RDFDataMgr.read(model, new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)), base, lang);
        } catch (StackOverflowError tooDeep) {
            throw new TooDeeplyNestedException(); // a backstop; requireShallow should have refused it
        }
        return model;
    }

    /**
     * Parses JSON-LD properly — through Jena's JSON-LD 1.1 reader (Titanium) — so a conforming
     * controlled identifier document verifies whatever shape it is written in: aliased terms, an
     * {@code @graph}, embedded or referenced verification methods, additional contexts.
     *
     * <p>The verifiers previously pattern-matched the JSON, walking the exact key names this project
     * itself emits. That works against documents this provider serves and fails against equally
     * conforming documents from any other LWS implementation, which is an interoperability bug rather
     * than a strictness one.</p>
     *
     * <p>Contexts resolve through {@link LocalJsonLdContexts}, so parsing makes no network request: a
     * JSON-LD processor left to itself would fetch every {@code @context} URL the document names, which
     * would be an unvetted outbound fetch during verification.</p>
     *
     * @throws TooDeeplyNestedException if the document nests deeper than {@link #MAX_NESTING_DEPTH}
     * @throws RuntimeException if the document is not valid JSON-LD, or names a context this provider
     *                          does not bundle
     */
    public static Model parseJsonLd(String body, String base) {
        requireShallow(body, true);
        JsonLdOptions options = new JsonLdOptions();
        options.setDocumentLoader(LocalJsonLdContexts.INSTANCE);

        Context context = new Context();
        context.set(TitaniumJsonLdOptions.JSONLD_OPTIONS, options);

        Model model = ModelFactory.createDefaultModel();
        try {
            RDFParser.create()
                    .source(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)))
                    .base(base)
                    .lang(Lang.JSONLD11)
                    .context(context)
                    .parse(model);
        } catch (StackOverflowError tooDeep) {
            throw new TooDeeplyNestedException(); // a backstop; requireShallow should have refused it
        }
        return model;
    }

    /**
     * Refuses a document that nests deeper than {@link #MAX_NESTING_DEPTH}, in one pass and without
     * recursion. Brackets are counted outside strings — and, in Turtle, outside IRIs and comments and
     * after a backslash — so the count can only overstate the depth of a malformed document, which the
     * parser would refuse anyway.
     *
     * @param json JSON (counting {@code {} and {@code [}) rather than Turtle ({@code [} and {@code (})
     * @throws TooDeeplyNestedException if it does
     */
    static void requireShallow(String body, boolean json) {
        int depth = 0;
        int n = body.length();
        for (int i = 0; i < n; i++) {
            char c = body.charAt(i);
            switch (c) {
                case '{', '[', '(' -> {
                    if (++depth > MAX_NESTING_DEPTH) {
                        throw new TooDeeplyNestedException();
                    }
                }
                case '}', ']', ')' -> depth = Math.max(0, depth - 1);
                case '"' -> i = endOfString(body, i, '"');
                case '\\' -> i++; // Turtle: an escaped character in a prefixed name
                case '\'' -> {
                    if (!json) {
                        i = endOfString(body, i, '\'');
                    }
                }
                case '<' -> {
                    if (!json) {
                        int close = body.indexOf('>', i + 1);
                        i = close < 0 ? n : close;
                    }
                }
                case '#' -> {
                    if (!json) {
                        while (i + 1 < n && body.charAt(i + 1) != '\n' && body.charAt(i + 1) != '\r') {
                            i++;
                        }
                    }
                }
                default -> { }
            }
        }
    }

    /**
     * The index of the quote that closes the string opening at {@code start}, or the end of the body if
     * none does. A tripled quote opens a Turtle long string, which only a tripled quote closes.
     */
    private static int endOfString(String body, int start, char quote) {
        int n = body.length();
        boolean isLong = start + 2 < n && body.charAt(start + 1) == quote && body.charAt(start + 2) == quote;
        for (int i = start + (isLong ? 3 : 1); i < n; i++) {
            char c = body.charAt(i);
            if (c == '\\') {
                i++;
            } else if (c == quote && (!isLong || (i + 2 < n && body.charAt(i + 1) == quote
                    && body.charAt(i + 2) == quote))) {
                return isLong ? i + 2 : i;
            }
        }
        return n;
    }

    /**
     * Parses a dereferenced document in whatever syntax it arrived in, returning an RDF graph.
     *
     * @return the parsed graph, or {@code null} if it was JSON-LD that could not be processed — the
     *         caller may then fall back to reading the compact shape directly, which is what this
     *         provider did for every JSON-LD document before {@link #parseJsonLd} existed
     * @throws UnsupportedSyntaxException if the document declares a content type that is not an RDF
     *                                    syntax this verifier reads
     * @throws TooDeeplyNestedException   if it nests deeper than {@link #MAX_NESTING_DEPTH}
     */
    public static Model parse(String body, String contentType, String base) {
        // Checked before isJsonLd, whose {-sniff is a fallback for a document that declares no type at
        // all and must not be allowed to rescue one that declares the wrong one: an HTML error page
        // whose body happens to start with a brace is not a JSON-LD document, and neither is it Turtle.
        requireSupported(contentType);
        if (!isJsonLd(contentType, body)) {
            return parseRdf(body, contentType, base);
        }
        try {
            return parseJsonLd(body, base);
        } catch (TooDeeplyNestedException tooDeep) {
            throw tooDeep; // not a shape to fall back from: the compact reader is no answer to it
        } catch (RuntimeException notProcessable) {
            return null;
        }
    }
}
