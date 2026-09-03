/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Controlled identifier document (W3C CID 1.0) for the self-signed identity suite: it publishes the
 * subject's public key(s) as {@code authentication} verification methods of type {@code JsonWebKey}.
 */
package com.ebremer.lws.authn.ssicid.cid;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import org.apache.jena.datatypes.RDFDatatype;
import org.apache.jena.datatypes.TypeMapper;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.riot.RDFFormat;
import org.apache.jena.vocabulary.RDF;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.jose.KeyIdFragment;
import com.ebremer.lws.authn.jose.PublicJwk;
import com.ebremer.lws.authn.ssicid.SsiCidConstants;

/**
 * Builds, and serializes in several RDF syntaxes, the self-signed-suite controlled identifier
 * document, matching the specification's example shape:
 *
 * <pre>
 * {
 *   "@context": ["https://www.w3.org/ns/cid/v1"],
 *   "id": "&lt;subject&gt;",
 *   "authentication": [{
 *     "id": "&lt;subject&gt;#&lt;kid&gt;",
 *     "type": "JsonWebKey",
 *     "controller": "&lt;subject&gt;",
 *     "publicKeyJwk": { ... }
 *   }]
 * }
 * </pre>
 *
 * @author Erich Bremer
 */
public final class SelfSignedControlledIdentifierDocument {

    private final String id;
    private final List<JsonNode> publicKeyJwks; // each a public-only JWK object, ideally carrying a "kid"

    /**
     * @param id            the controlled identifier this document describes
     * @param publicKeyJwks candidate JWKs. Each is passed through {@link PublicJwk#sanitize} and is
     *                      silently skipped if it is not publishable — this document is served to
     *                      anyone, so no caller can make it emit private key material, whatever it
     *                      passes in. Callers that want to tell an operator <em>why</em> a key was
     *                      dropped should filter first and log {@link PublicJwk#describeRejection}.
     *                      A JWK whose {@code kid} cannot be a legal IRI fragment (see
     *                      {@link KeyIdFragment}) is still published, under a synthesized identifier.
     */
    public SelfSignedControlledIdentifierDocument(String id, List<JsonNode> publicKeyJwks) {
        this.id = id;
        this.publicKeyJwks = publicKeyJwks == null ? List.of()
                : publicKeyJwks.stream().map(PublicJwk::sanitize).flatMap(java.util.Optional::stream).toList();
    }

    /**
     * The identifier of the {@code n}-th published verification method.
     *
     * <p>CID 1.0 requires every verification method to have an {@code id} that "MUST be a string
     * conforming to URL syntax", so one is always produced. The {@code kid} supplies the fragment when
     * it can be percent-encoded into one ({@link KeyIdFragment}); when it cannot — absent, blank,
     * absurdly long, or not well-formed text — the position stands in, which is positional and so
     * shifts if keys are added or removed, but is a conforming identifier where there was none.
     * A verifier selects by the JWK's own {@code kid} first in any case.</p>
     */
    private String methodId(JsonNode jwk, int index) {
        return KeyIdFragment.methodId(id, jwk.path("kid").asText(null))
                .orElseGet(() -> id + "#key-" + (index + 1));
    }

    /** Compact JSON-LD form (the canonical document; the JWK is naturally a JSON object). */
    public String toJsonLd() {
        List<Object> methods = new ArrayList<>();
        for (int i = 0; i < publicKeyJwks.size(); i++) {
            JsonNode jwk = publicKeyJwks.get(i);
            Map<String, Object> method = new LinkedHashMap<>();
            method.put("id", methodId(jwk, i));
            method.put("type", "JsonWebKey");
            method.put("controller", id);
            method.put("publicKeyJwk", jwk);
            methods.add(method);
        }

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("@context", List.of(SsiCidConstants.CID_CONTEXT));
        doc.put("id", id);
        if (!methods.isEmpty()) {
            doc.put("authentication", methods);
        }
        try {
            return JsonSerialization.writeValueAsPrettyString(doc);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize controlled identifier document", e);
        }
    }

    /** Builds the RDF graph (publicKeyJwk is emitted as an {@code rdf:JSON} literal). */
    public Model toModel() {
        Model model = ModelFactory.createDefaultModel();
        Resource subject = model.createResource(id);
        Property authentication = model.createProperty(SsiCidConstants.SEC_AUTHENTICATION);
        Property controller = model.createProperty(SsiCidConstants.SEC_CONTROLLER);
        Property publicKeyJwk = model.createProperty(SsiCidConstants.SEC_PUBLIC_KEY_JWK);
        RDFDatatype jsonType = TypeMapper.getInstance().getSafeTypeByName(SsiCidConstants.RDF_JSON);

        for (int i = 0; i < publicKeyJwks.size(); i++) {
            JsonNode jwk = publicKeyJwks.get(i);
            Resource method = model.createResource(methodId(jwk, i));
            method.addProperty(RDF.type, model.createResource(SsiCidConstants.JSON_WEB_KEY_TYPE));
            method.addProperty(controller, subject);
            method.addProperty(publicKeyJwk, model.createTypedLiteral(jwk.toString(), jsonType));
            subject.addProperty(authentication, method);
        }
        return model;
    }

    /** Serializes the graph using a Jena RDF syntax (Turtle, N-Triples, RDF/XML, ...). */
    public String toRdf(RDFFormat format) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        RDFDataMgr.write(out, toModel(), format);
        return out.toString(StandardCharsets.UTF_8);
    }
}
