/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * The JSON-LD context loader used when parsing a dereferenced controlled identifier document.
 */
package com.ebremer.lws.authn.rdf;

import java.io.InputStream;
import java.net.URI;
import java.util.Map;

import com.apicatalog.jsonld.JsonLdError;
import com.apicatalog.jsonld.JsonLdErrorCode;
import com.apicatalog.jsonld.document.Document;
import com.apicatalog.jsonld.document.JsonDocument;
import com.apicatalog.jsonld.http.media.MediaType;
import com.apicatalog.jsonld.loader.DocumentLoader;
import com.apicatalog.jsonld.loader.DocumentLoaderOptions;

/**
 * Serves the JSON-LD contexts a controlled identifier document may reference, from copies bundled in
 * this JAR, and refuses every other URL.
 *
 * <p>A JSON-LD processor resolves {@code @context} URLs by fetching them. Left to itself that would
 * mean this server making an HTTP request to whatever URL a credential's document happens to name —
 * an unvetted outbound fetch during credential verification, which is exactly what
 * {@link com.ebremer.lws.authn.net.SsrfGuard} exists to prevent, and a hard dependency on
 * {@code w3.org} being reachable for any verification to succeed.</p>
 *
 * <p>So the loader is closed by default: known contexts come from disk, and anything else fails the
 * parse rather than reaching the network. A document using a context this provider does not bundle is
 * refused as unverifiable, which is the honest outcome — the alternative is guessing at the meaning of
 * terms whose definitions were never read.</p>
 *
 * @author Erich Bremer
 */
public final class LocalJsonLdContexts implements DocumentLoader {

    /** The single shared instance; the bundled documents are immutable. */
    public static final LocalJsonLdContexts INSTANCE = new LocalJsonLdContexts();

    /**
     * Context URL to the classpath resource holding it.
     *
     * <p>{@code cid/v1} is the context W3C Controlled Identifiers 1.0 defines and every LWS
     * authentication suite's example uses. The bundled copy is the one published at that URL; refresh
     * it deliberately, since changing it changes how every credential's document is interpreted.</p>
     */
    private static final Map<String, String> BUNDLED = Map.of(
            "https://www.w3.org/ns/cid/v1", "/contexts/cid-v1.jsonld");

    private LocalJsonLdContexts() {
    }

    @Override
    public Document loadDocument(URI url, DocumentLoaderOptions options) throws JsonLdError {
        String resource = url == null ? null : BUNDLED.get(url.toString());
        if (resource == null) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED,
                    "refusing to fetch a JSON-LD context that is not bundled: " + url);
        }
        try (InputStream in = LocalJsonLdContexts.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new JsonLdError(JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED,
                        "bundled JSON-LD context is missing from the provider JAR: " + resource);
            }
            return JsonDocument.of(MediaType.JSON_LD, in);
        } catch (JsonLdError e) {
            throw e;
        } catch (Exception e) {
            throw new JsonLdError(JsonLdErrorCode.LOADING_REMOTE_CONTEXT_FAILED,
                    "could not read the bundled JSON-LD context " + resource);
        }
    }

    /** The context URLs this provider can resolve without network access. */
    public static java.util.Set<String> bundledContexts() {
        return BUNDLED.keySet();
    }
}
