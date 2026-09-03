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

import com.apicatalog.jsonld.JsonLdOptions;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.riot.RDFLanguages;
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
     * Decides whether a dereferenced document should be read as JSON-LD: by content type when one is
     * present and recognised, otherwise by sniffing a leading {@code {} / {@code [}.
     */
    public static boolean isJsonLd(String contentType, String body) {
        if (contentType != null) {
            String ct = contentType.split(";")[0].trim().toLowerCase(Locale.ROOT);
            if (ct.equals(JSON_LD) || ct.equals("application/json")) {
                return true;
            }
            if (RDFLanguages.contentTypeToLang(ct) != null) {
                return false; // a recognized non-JSON RDF syntax
            }
        }
        String trimmed = body == null ? "" : body.trim();
        return trimmed.startsWith("{") || trimmed.startsWith("[");
    }

    /** Parses Turtle / N-Triples / RDF/XML with Jena RIOT, defaulting to Turtle. */
    public static Model parseRdf(String body, String contentType, String base) {
        Lang lang = Lang.TURTLE;
        if (contentType != null) {
            Lang detected = RDFLanguages.contentTypeToLang(contentType.split(";")[0].trim());
            if (detected != null) {
                lang = detected;
            }
        }
        Model model = ModelFactory.createDefaultModel();
        RDFDataMgr.read(model, new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)), base, lang);
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
     * @throws RuntimeException if the document is not valid JSON-LD, or names a context this provider
     *                          does not bundle
     */
    public static Model parseJsonLd(String body, String base) {
        JsonLdOptions options = new JsonLdOptions();
        options.setDocumentLoader(LocalJsonLdContexts.INSTANCE);

        Context context = new Context();
        context.set(TitaniumJsonLdOptions.JSONLD_OPTIONS, options);

        Model model = ModelFactory.createDefaultModel();
        RDFParser.create()
                .source(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)))
                .base(base)
                .lang(Lang.JSONLD11)
                .context(context)
                .parse(model);
        return model;
    }

    /**
     * Parses a dereferenced document in whatever syntax it arrived in, returning an RDF graph.
     *
     * @return the parsed graph, or {@code null} if it was JSON-LD that could not be processed — the
     *         caller may then fall back to reading the compact shape directly, which is what this
     *         provider did for every JSON-LD document before {@link #parseJsonLd} existed
     */
    public static Model parse(String body, String contentType, String base) {
        if (!isJsonLd(contentType, body)) {
            return parseRdf(body, contentType, base);
        }
        try {
            return parseJsonLd(body, base);
        } catch (RuntimeException notProcessable) {
            return null;
        }
    }
}
