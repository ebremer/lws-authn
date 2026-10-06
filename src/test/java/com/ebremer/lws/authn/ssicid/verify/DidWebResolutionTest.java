/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.ssicid.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.ebremer.lws.authn.did.DidKey;
import com.ebremer.lws.authn.did.Dids;
import com.ebremer.lws.authn.net.OutboundHttp;
import com.ebremer.lws.authn.testsupport.SelfIssuedJwts;

/**
 * R-44. Resolving a {@code did:web} subject, which had no test at all: what the verifier makes of each
 * thing the DID's web server may answer. The did:web method maps the DID to an {@code https:} URL, so
 * the answers come from the verifier's fetch seam rather than from a TLS server; the DID-to-URL mapping
 * itself is DidsTest's.
 *
 * <p>Each refusal is set up so that the rule under test is the only thing refusing: the body that comes
 * back is the DID's real, correctly signed-for document wherever the rule allows one.</p>
 */
class DidWebResolutionTest {

    private static final String DID = "did:web:cid.example:alice";
    private static final String KID = DID + "#k1";

    /** One answer from the DID's web server, with the requests the verifier made recorded. */
    private static final class Answer implements SelfSignedCidVerifier.Fetcher {
        private final OutboundHttp.Fetched response;
        private final IOException failure;
        final List<String> requests = new ArrayList<>();

        Answer(int status, String contentType, String body) {
            this.response = new OutboundHttp.Fetched(status, contentType, body);
            this.failure = null;
        }

        Answer(IOException failure) {
            this.response = null;
            this.failure = failure;
        }

        @Override
        public OutboundHttp.Fetched fetch(String url, String accept, boolean followRedirects) throws IOException {
            requests.add(url + " | " + accept + " | redirects=" + followRedirects);
            if (failure != null) {
                throw failure;
            }
            return response;
        }
    }

    /** A DID document with {@code id} as its id and one Multikey method, {@link #KID}, holding {@code pair}'s key. */
    private static String document(String id, KeyPair pair) {
        String key = DidKey.multibaseValue(DidKey.encodeEd25519(pair.getPublic()));
        return "{\"@context\":[\"https://www.w3.org/ns/did/v1.1\"],\"id\":\"" + id + "\","
                + "\"verificationMethod\":[{\"id\":\"" + KID + "\",\"type\":\"Multikey\",\"controller\":\"" + DID
                + "\",\"publicKeyMultibase\":\"" + key + "\"}],\"authentication\":[\"" + KID + "\"]}";
    }

    private static String credential(KeyPair pair) throws Exception {
        return SelfIssuedJwts.sign(SelfIssuedJwts.claims(DID), "EdDSA", KID, pair.getPrivate(), "Ed25519");
    }

    private static SsiCidVerificationResult verify(KeyPair pair, Answer answer) throws Exception {
        return new SelfSignedCidVerifier(null).fetchingWith(answer).verify(credential(pair), SelfIssuedJwts.AUDIENCE);
    }

    private static void assertRejected(SsiCidVerificationResult result, String failedCheck) {
        assertFalse(result.isValid(), "expected a rejection at " + failedCheck);
        assertEquals(Boolean.FALSE, result.getChecks().get(failedCheck),
                () -> failedCheck + " should have failed; checks=" + result.getChecks() + " errors=" + result.getErrors());
    }

    /**
     * The control: a did:web document at the URL the method gives, as {@code application/did+json}, with
     * or without parameters, or with no {@code Content-Type} at all, verifies. It is fetched once, from
     * exactly that URL, asking for DID documents, and following no redirect — the URL is the trust anchor.
     */
    @Test
    void aDidWebSubjectResolvesAndVerifies() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        for (String type : new String[]{"application/did+json", "application/did+ld+json",
                "application/json; charset=utf-8", "application/ld+json", null}) {
            Answer answer = new Answer(200, type, document(DID, pair));
            SsiCidVerificationResult result = verify(pair, answer);
            assertTrue(result.isValid(), () -> type + ": checks=" + result.getChecks() + " errors=" + result.getErrors());
            assertEquals(List.of("https://cid.example/alice/did.json | " + Dids.DID_DOCUMENT_ACCEPT + " | redirects=false"),
                    answer.requests);
        }
    }

    /**
     * R-44. Only a {@code 200} is a DID document — and a redirect is not followed, so a {@code 3xx} is
     * refused too, whatever its body.
     */
    @Test
    void anAnswerOtherThan200IsNotADidDocument() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        for (int status : new int[]{201, 204, 301, 302, 303, 307, 404, 410, 500, 503}) {
            SsiCidVerificationResult result = verify(pair, new Answer(status, "application/did+json", document(DID, pair)));
            assertRejected(result, "subjectDereferenced");
            assertTrue(result.getErrors().toString().contains("did not return a DID document"),
                    status + ": " + result.getErrors());
        }
    }

    /**
     * R-44. A document served as something that is not a DID document media type — an HTML error page,
     * Turtle, a CID — is refused, by the media type's name, even when the bytes would have read as one.
     */
    @Test
    void aDocumentServedAsAnotherMediaTypeIsRefusedByName() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        for (String type : new String[]{"text/html", "text/turtle", "application/cid", "text/plain; charset=utf-8"}) {
            SsiCidVerificationResult result = verify(pair, new Answer(200, type, document(DID, pair)));
            assertRejected(result, "subjectDereferenced");
            String bare = type.split(";")[0];
            assertTrue(result.getErrors().toString().contains("'" + bare + "'"), type + ": " + result.getErrors());
        }
    }

    /**
     * R-44. A DID document is a JSON object (DID 1.1 §6.2.1). An array holding the real document, a
     * string, {@code null} or a number is not one; nor is JSON that does not parse.
     */
    @Test
    void aBodyThatIsNotAJsonObjectIsNotADidDocument() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        for (String body : new String[]{"[" + document(DID, pair) + "]", "\"" + DID + "\"", "null", "42",
                document(DID, pair).substring(0, 40)}) {
            SsiCidVerificationResult result = verify(pair, new Answer(200, "application/did+json", body));
            assertRejected(result, "subjectDereferenced");
            assertEquals(null, result.getChecks().get("subjectIdMatches"), body);
        }
    }

    /**
     * R-44. did:web, Read: "Verify that the ID of the resolved DID document matches the Web DID being
     * resolved." A document copied from another DID — keys and all — or one with no {@code id}, is not
     * this DID's, however it was fetched.
     */
    @Test
    void aDocumentForAnotherDidIsRejected() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        for (String id : new String[]{"did:web:attacker.example:alice", "did:web:cid.example", DID + ":", "https://cid.example/alice"}) {
            SsiCidVerificationResult result = verify(pair, new Answer(200, "application/did+json", document(id, pair)));
            assertRejected(result, "subjectIdMatches");
            assertEquals(Boolean.TRUE, result.getChecks().get("subjectDereferenced"), "a document was read: " + id);
        }
        String noId = document(DID, pair).replace("\"id\":\"" + DID + "\",", "");
        assertRejected(verify(pair, new Answer(200, "application/did+json", noId)), "subjectIdMatches");
    }

    /**
     * R-44. A fetch that fails is reported as that, and never with its cause: the exception can name the
     * address the host resolved to, which the caller is not told.
     */
    @Test
    void aFailedFetchIsReportedWithoutItsCause() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        SsiCidVerificationResult result = verify(pair,
                new Answer(new IOException("Connect to cid.example/10.20.30.40:443 timed out")));
        assertRejected(result, "subjectDereferenced");
        assertFalse(result.getErrors().toString().contains("10.20.30.40"), result.getErrors().toString());
    }
}
