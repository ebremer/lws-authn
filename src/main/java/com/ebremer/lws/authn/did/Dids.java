/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * The side-effect-free half of DID resolution for the self-signed CID suite: DID syntax (DID 1.1
 * §3.1), expanding a did:key into its DID document ("The did:key Method" v0.9, Read), and turning a
 * did:web into the HTTPS URL of its DID document ("did:web Method Specification", Read). The network
 * fetch a did:web needs is done by the verifier, through the SSRF-guarded client.
 */
package com.ebremer.lws.authn.did;

import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Decentralized Identifiers as LWS subject identifiers.
 *
 * <p>The self-signed CID suite states that it "is designed to work with subject identifiers that use
 * HTTPS URIs as well as DID URIs", because a DID document is an extension of a controlled identifier
 * document (DID 1.1 §5). The suite does not mandate any DID method. This provider resolves the two
 * that need no ledger and no third-party resolver:</p>
 *
 * <ul>
 *   <li><strong>{@code did:key}</strong> — the document is generated from the key the identifier
 *       embeds, locally, with nothing to fetch. This is what the discontinued did:key suite covered,
 *       now expressed as the "generalization" the self-signed CID suite subsumes it with.</li>
 *   <li><strong>{@code did:web}</strong> — the document is fetched from a well-known HTTPS URL on the
 *       domain the identifier names, the same kind of fetch an HTTPS subject needs.</li>
 * </ul>
 *
 * <p>Any other method is refused by name rather than guessed at.</p>
 *
 * @author Erich Bremer
 */
public final class Dids {

    private Dids() {
    }

    public static final String DID_PREFIX = "did:";
    public static final String METHOD_KEY = "key";
    public static final String METHOD_WEB = "web";

    /** The DID methods this provider resolves, as {@code did:<method>}. */
    public static final List<String> SUPPORTED_METHODS = List.of("did:" + METHOD_KEY, "did:" + METHOD_WEB);

    /**
     * DID 1.1 §3.1:
     * <pre>
     * did                = "did:" method-name ":" method-specific-id
     * method-name        = 1*method-char
     * method-char        = %x61-7A / DIGIT
     * method-specific-id = *( *idchar ":" ) 1*idchar
     * idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
     * </pre>
     * No {@code /}, {@code ?} or {@code #}: a DID is the identifier itself, never a DID URL.
     */
    private static final String IDCHAR = "(?:[A-Za-z0-9._-]|%[0-9A-Fa-f]{2})";
    private static final Pattern DID = Pattern.compile(
            "^did:([a-z0-9]+):((?:" + IDCHAR + "*:)*" + IDCHAR + "+)$");

    /** A DNS name label: letters, digits and hyphens, not starting or ending with a hyphen. */
    private static final Pattern LABEL = Pattern.compile("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$");

    /** Thrown for a string that is not a syntactically valid DID, or not a valid DID of its method. */
    public static final class InvalidDidException extends IllegalArgumentException {
        public InvalidDidException(String message) {
            super(message);
        }
    }

    /** Thrown for a valid DID whose method this provider does not resolve. */
    public static final class UnsupportedDidMethodException extends IllegalArgumentException {
        private final String method;

        public UnsupportedDidMethodException(String method) {
            super("did:" + method + " is not a DID method this verifier resolves (supported: "
                    + String.join(", ", SUPPORTED_METHODS) + ")");
            this.method = method;
        }

        public String getMethod() {
            return method;
        }
    }

    /** True iff {@code identifier} uses the {@code did} URI scheme (it may still be invalid). */
    public static boolean isDid(String identifier) {
        return identifier != null && identifier.startsWith(DID_PREFIX);
    }

    /**
     * The method name of a syntactically valid DID.
     *
     * @throws InvalidDidException if {@code did} is not one
     */
    public static String methodOf(String did) {
        var matcher = did == null ? null : DID.matcher(did);
        if (matcher == null || !matcher.matches()) {
            throw new InvalidDidException("not a syntactically valid DID");
        }
        return matcher.group(1);
    }

    // ----------------------------------------------------------------------------------- did:key

    /**
     * The DID document a {@code did:key} expands to — the did:key Method's Document Creation
     * Algorithm, with its default {@code Multikey} public key format:
     *
     * <pre>
     * {
     *   "@context": ["https://www.w3.org/ns/did/v1.1"],
     *   "id": "did:key:z…",
     *   "verificationMethod": [{
     *     "id": "did:key:z…#z…", "type": "Multikey",
     *     "controller": "did:key:z…", "publicKeyMultibase": "z…" }],
     *   "authentication":       ["did:key:z…#z…"],
     *   "assertionMethod":      ["did:key:z…#z…"],
     *   "capabilityInvocation": ["did:key:z…#z…"],
     *   "capabilityDelegation": ["did:key:z…#z…"]
     * }
     * </pre>
     *
     * <p>No {@code keyAgreement} method is derived: the option that enables it defaults off, and a key
     * agreement key cannot authenticate anyway.</p>
     *
     * @throws InvalidDidException if {@code did} is not a canonically encoded did:key of a supported
     *                             key type
     */
    public static ObjectNode didKeyDocument(String did) {
        if (!METHOD_KEY.equals(methodOf(did))) {
            throw new InvalidDidException("not a did:key");
        }
        String multibase;
        try {
            multibase = DidKey.multibaseValue(did);
            DidKey.decodeMultibase(multibase);   // supported key type, canonical encoding
        } catch (IllegalArgumentException e) {
            throw new InvalidDidException("not a resolvable did:key: " + e.getMessage());
        }
        String methodId = did + "#" + multibase;

        JsonNodeFactory json = JsonNodeFactory.instance;
        ObjectNode doc = json.objectNode();
        doc.putArray("@context").add("https://www.w3.org/ns/did/v1.1");
        doc.put("id", did);
        ObjectNode method = doc.putArray("verificationMethod").addObject();
        method.put("id", methodId);
        method.put("type", "Multikey");
        method.put("controller", did);
        method.put("publicKeyMultibase", multibase);
        for (String relationship : List.of("authentication", "assertionMethod",
                "capabilityInvocation", "capabilityDelegation")) {
            ArrayNode refs = doc.putArray(relationship);
            refs.add(methodId);
        }
        return doc;
    }

    // ----------------------------------------------------------------------------------- did:web

    /**
     * The HTTPS URL of a {@code did:web}'s DID document, per the method's Read operation:
     *
     * <pre>
     * did:web:w3c-ccg.github.io                     → https://w3c-ccg.github.io/.well-known/did.json
     * did:web:w3c-ccg.github.io:user:alice          → https://w3c-ccg.github.io/user/alice/did.json
     * did:web:example.com%3A3000:user:alice         → https://example.com:3000/user/alice/did.json
     * </pre>
     *
     * <p>The method-specific identifier "is a fully qualified domain name" and "MUST NOT include IP
     * addresses"; a port is allowed only as a percent-encoded colon. Anything else about the host is
     * refused here rather than handed to the HTTP client.</p>
     *
     * @throws InvalidDidException if {@code did} is not a valid did:web
     */
    public static String didWebUrl(String did) {
        if (!METHOD_WEB.equals(methodOf(did))) {
            throw new InvalidDidException("not a did:web");
        }
        String[] parts = did.substring((DID_PREFIX + METHOD_WEB + ":").length()).split(":", -1);

        String authority = parts[0];
        String host = authority;
        String port = null;
        int encodedColon = authority.toLowerCase(Locale.ROOT).indexOf("%3a");
        if (encodedColon >= 0) {
            host = authority.substring(0, encodedColon);
            port = authority.substring(encodedColon + 3);
            if (!port.matches("[0-9]{1,5}") || Integer.parseInt(port) < 1 || Integer.parseInt(port) > 65535) {
                throw new InvalidDidException("did:web port is not a number from 1 to 65535");
            }
        }
        if (!isDomainName(host)) {
            throw new InvalidDidException("did:web must name a fully qualified domain name, not an IP address "
                    + "or anything else");
        }

        StringBuilder url = new StringBuilder("https://").append(host);
        if (port != null) {
            url.append(':').append(port);
        }
        if (parts.length == 1) {
            url.append("/.well-known");
        } else {
            for (int i = 1; i < parts.length; i++) {
                if (parts[i].isEmpty()) {
                    throw new InvalidDidException("did:web path has an empty segment");
                }
                url.append('/').append(parts[i]);
            }
        }
        return url.append("/did.json").toString();
    }

    /**
     * True iff {@code host} is a DNS name: dot-separated labels of letters, digits and hyphens, whose
     * last label is not all digits (which also rules out a dotted-quad IPv4 address). IPv6 literals
     * cannot get this far — {@code [} is not a DID character.
     */
    static boolean isDomainName(String host) {
        if (host == null || host.isEmpty() || host.length() > 253) {
            return false;
        }
        String[] labels = host.split("\\.", -1);
        for (String label : labels) {
            if (!LABEL.matcher(label).matches()) {
                return false;
            }
        }
        return !labels[labels.length - 1].matches("[0-9]+");
    }

    // ------------------------------------------------------------------------------ media types

    /** {@code Accept} header for fetching a DID document. */
    public static final String DID_DOCUMENT_ACCEPT = "application/did+json, application/did+ld+json;q=0.9, "
            + "application/did;q=0.9, application/ld+json;q=0.8, application/json;q=0.7";

    /**
     * True iff a {@code Content-Type} is one a DID document may be served with — the DID media types,
     * or plain JSON / JSON-LD, which the did:web method expects most servers to use — or is absent.
     */
    public static boolean isDidDocumentMediaType(String contentType) {
        if (contentType == null || contentType.isBlank()) {
            return true;
        }
        String bare = contentType.split(";")[0].trim().toLowerCase(Locale.ROOT);
        return bare.equals("application/did+json") || bare.equals("application/did+ld+json")
                || bare.equals("application/did") || bare.equals("application/ld+json")
                || bare.equals("application/json");
    }
}
