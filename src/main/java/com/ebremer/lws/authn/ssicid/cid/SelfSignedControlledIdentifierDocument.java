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
    private final List<Method> methods;
    private final List<String> refusedMethodIds;

    /** One published verification method: its identifier and its public-only JWK. */
    private record Method(String id, JsonNode jwk) {
    }

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
        List<JsonNode> publishable = publicKeyJwks == null ? List.of()
                : publicKeyJwks.stream().map(PublicJwk::sanitize).flatMap(java.util.Optional::stream).toList();
        List<String> refused = new ArrayList<>();
        this.methods = assignIds(id, publishable, refused);
        this.refusedMethodIds = List.copyOf(refused);
    }

    /**
     * Gives each JWK its verification method identifier, once, so that no two methods share one (R-33).
     *
     * <p>CID 1.0 requires every verification method to have an {@code id} that "MUST be a string
     * conforming to URL syntax", so one is always produced. The {@code kid} supplies the fragment when
     * it can be percent-encoded into one ({@link KeyIdFragment}); when it cannot — absent, blank,
     * absurdly long, or not well-formed text — the position stands in, which is positional and so
     * shifts if keys are added or removed, but is a conforming identifier where there was none.
     * A verifier matches a credential's {@code kid} against this identifier — whole, then its fragment —
     * and only then against the JWK's own {@code kid}, so a positional id still leaves the key
     * selectable by the {@code kid} it was registered with.</p>
     *
     * <p>Two methods with one identifier are one node in RDF, holding two keys, and a verifier reading
     * the document back collected only one of them, so tokens signed with the other failed. So:</p>
     * <ul>
     *   <li>the same JWK registered twice is published once;</li>
     *   <li>different JWKs under one {@code kid} are not published at all — which of them a token naming
     *       that {@code kid} meant cannot be known — and their identifier is reported by
     *       {@link #refusedMethodIds()};</li>
     *   <li>a positional {@code #key-<n>} skips any identifier a {@code kid} already took, so a key
     *       registered as {@code kid: "key-2"} and a {@code kid}-less one after it no longer collide.</li>
     * </ul>
     */
    private static List<Method> assignIds(String id, List<JsonNode> jwks, List<String> refused) {
        String[] ids = new String[jwks.size()];
        Map<String, List<Integer>> byId = new LinkedHashMap<>();
        for (int i = 0; i < jwks.size(); i++) {
            ids[i] = KeyIdFragment.methodId(id, jwks.get(i).path("kid").asText(null)).orElse(null);
            if (ids[i] != null) {
                byId.computeIfAbsent(ids[i], k -> new ArrayList<>()).add(i);
            }
        }
        java.util.Set<Integer> dropped = new java.util.HashSet<>();
        for (Map.Entry<String, List<Integer>> entry : byId.entrySet()) {
            List<Integer> holders = entry.getValue();
            if (holders.size() < 2) {
                continue;
            }
            JsonNode first = jwks.get(holders.get(0));
            boolean sameKey = holders.stream().allMatch(i -> jwks.get(i).equals(first));
            dropped.addAll(sameKey ? holders.subList(1, holders.size()) : holders);
            if (!sameKey) {
                refused.add(entry.getKey());
            }
        }
        java.util.Set<String> taken = new java.util.HashSet<>(byId.keySet());
        List<Method> methods = new ArrayList<>();
        for (int i = 0; i < jwks.size(); i++) {
            if (dropped.contains(i)) {
                continue;
            }
            if (ids[i] == null) {
                int n = i + 1;
                while (taken.contains(id + "#key-" + n)) {
                    n++;
                }
                ids[i] = id + "#key-" + n;
                taken.add(ids[i]);
            }
            methods.add(new Method(ids[i], jwks.get(i)));
        }
        return methods;
    }

    /**
     * The identifiers that more than one different key claimed, none of which was published (R-33): for
     * the caller to tell the operator.
     */
    public List<String> refusedMethodIds() {
        return refusedMethodIds;
    }

    /** Compact JSON-LD form (the canonical document; the JWK is naturally a JSON object). */
    public String toJsonLd() {
        List<Object> authentication = new ArrayList<>();
        for (Method published : methods) {
            Map<String, Object> method = new LinkedHashMap<>();
            method.put("id", published.id());
            method.put("type", "JsonWebKey");
            method.put("controller", id);
            method.put("publicKeyJwk", published.jwk());
            authentication.add(method);
        }

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("@context", List.of(SsiCidConstants.CID_CONTEXT));
        doc.put("id", id);
        if (!authentication.isEmpty()) {
            doc.put("authentication", authentication);
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

        for (Method published : methods) {
            Resource method = model.createResource(published.id());
            method.addProperty(RDF.type, model.createResource(SsiCidConstants.JSON_WEB_KEY_TYPE));
            method.addProperty(controller, subject);
            method.addProperty(publicKeyJwk, model.createTypedLiteral(published.jwk().toString(), jsonType));
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
