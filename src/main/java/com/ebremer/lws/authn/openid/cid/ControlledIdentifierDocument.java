/*
 * Copyright Erich Bremer.
 *
 * Controlled identifier document (W3C CID 1.0) describing an LWS subject and the OpenID Provider
 * that issues its authentication credentials.
 */
package com.ebremer.lws.authn.openid.cid;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.riot.RDFFormat;
import org.apache.jena.vocabulary.RDF;
import org.keycloak.util.JsonSerialization;

import com.ebremer.lws.authn.openid.LWSConstants;

/**
 * Builds, and serializes in several RDF syntaxes, the controlled identifier document for an LWS
 * subject:
 *
 * <pre>
 * {
 *   "@context": ["https://www.w3.org/ns/cid/v1"],
 *   "id": "&lt;webid&gt;",
 *   "service": [{
 *     "type": "https://www.w3.org/ns/lws#OpenIdProvider",
 *     "serviceEndpoint": "&lt;issuer&gt;"
 *   }]
 * }
 * </pre>
 *
 * @author Erich Bremer
 */
public final class ControlledIdentifierDocument {

    private final String id;      // the WebID; equal to the subject of the credential and to this doc's URL
    private final String issuer;  // the OpenID Provider issuer (the service endpoint)

    public ControlledIdentifierDocument(String id, String issuer) {
        this.id = id;
        this.issuer = issuer;
    }

    /** The identifier of this document's OpenID Provider service entry. */
    private String serviceId() {
        return id + "#openid-provider";
    }

    /** Builds the RDF graph of this controlled identifier document. */
    public Model toModel() {
        Model model = ModelFactory.createDefaultModel();
        Property service = model.createProperty(LWSConstants.DID_SERVICE);
        Property serviceEndpoint = model.createProperty(LWSConstants.DID_SERVICE_ENDPOINT);

        Resource subject = model.createResource(id);
        // Named rather than a blank node: CID 1.0 makes a service `id` OPTIONAL, so this is not a
        // conformance fix, but a named service is addressable and is the shape most CID consumers
        // expect. A blank node cannot be referred to from anywhere else in the document.
        Resource svc = model.createResource(serviceId());
        svc.addProperty(RDF.type, model.createResource(LWSConstants.OPENID_PROVIDER_TYPE));
        svc.addProperty(serviceEndpoint, model.createResource(issuer));
        subject.addProperty(service, svc);
        return model;
    }

    /** Serializes the graph using a Jena RDF syntax (Turtle, N-Triples, RDF/XML, ...). */
    public String toRdf(RDFFormat format) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        RDFDataMgr.write(out, toModel(), format);
        return out.toString(StandardCharsets.UTF_8);
    }

    /**
     * Compact JSON-LD form, matching the LWS specification example exactly. Emitted directly (not via
     * RIOT) so the output keeps the compact {@code https://www.w3.org/ns/cid/v1} context and needs no
     * network access at serving time.
     */
    public String toJsonLd() {
        Map<String, Object> svc = new LinkedHashMap<>();
        svc.put("id", serviceId());
        svc.put("type", LWSConstants.OPENID_PROVIDER_TYPE);
        svc.put("serviceEndpoint", issuer);

        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("@context", List.of(LWSConstants.CID_CONTEXT));
        doc.put("id", id);
        doc.put("service", List.of(svc));

        try {
            return JsonSerialization.writeValueAsPrettyString(doc);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialize controlled identifier document", e);
        }
    }
}
