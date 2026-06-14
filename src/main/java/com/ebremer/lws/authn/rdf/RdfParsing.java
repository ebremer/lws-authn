/*
 * Copyright Erich Bremer.
 *
 * Content-type detection and parsing for the (arbitrary-syntax) controlled identifier documents the
 * OpenID and self-signed CID verifiers dereference. Shared by both verifiers so the syntax handling
 * stays identical.
 */
package com.ebremer.lws.authn.rdf;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.riot.RDFLanguages;

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
}
