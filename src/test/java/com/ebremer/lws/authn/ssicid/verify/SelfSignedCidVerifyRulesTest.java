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
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.ebremer.lws.authn.did.DidKey;
import com.ebremer.lws.authn.jose.JwsChecks;
import com.ebremer.lws.authn.net.OutboundHttp;
import com.ebremer.lws.authn.rdf.RdfParsing;
import com.ebremer.lws.authn.testsupport.SelfIssuedJwts;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * R-44. The self-signed CID suite's rules, each driven through {@link SelfSignedCidVerifier#verify} with
 * a credential that breaks only that rule, so deleting the rule fails a test. A verifier that wrongly
 * <em>accepts</em> is the failure nobody notices.
 *
 * <p>The claim and header rules use {@code did:key} subjects, which need no network. The rules about
 * what an HTTPS subject's server answers use the verifier's fetch seam, so a real {@code https:}
 * subject can be answered without a TLS server.</p>
 *
 * <p>Already pinned elsewhere, and not repeated here: a wrong {@code typ} ({@code at+jwt},
 * SelfSignedCidDidSubjectTest), an expired {@code exp}, a blank {@code aud}, {@code notReplayed}
 * (R-34, ibid.); plain http (SelfSignedCidVerifierTest); a document about another subject
 * (CidDocumentReadingTest, R-18).</p>
 */
class SelfSignedCidVerifyRulesTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static SsiCidVerificationResult verify(String jwt) {
        return new SelfSignedCidVerifier(null).verify(jwt, SelfIssuedJwts.AUDIENCE);
    }

    /** The did:key Method's verification method id: the DID, '#', and its multibase value. */
    private static String methodId(String did) {
        return did + "#" + DidKey.multibaseValue(did);
    }

    /** A JOSE header for an EdDSA credential, as {@link SelfIssuedJwts} writes one. */
    private static Map<String, Object> header(String kid) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "EdDSA");
        header.put("typ", "JWT");
        header.put("kid", kid);
        return header;
    }

    /** Signs {@code claims} under exactly {@code header}, which SelfIssuedJwts does not let a test choose. */
    private static String sign(Map<String, Object> header, Map<String, Object> claims, PrivateKey key) throws Exception {
        String input = b64(JSON.writeValueAsBytes(header)) + "." + b64(JSON.writeValueAsBytes(claims));
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(key);
        signature.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + b64(signature.sign());
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static void assertRejected(SsiCidVerificationResult result, String failedCheck) {
        assertFalse(result.isValid(), "expected a rejection at " + failedCheck);
        assertEquals(Boolean.FALSE, result.getChecks().get(failedCheck),
                () -> failedCheck + " should have failed; checks=" + result.getChecks() + " errors=" + result.getErrors());
    }

    private static void assertValid(SsiCidVerificationResult result) {
        assertTrue(result.isValid(), () -> "checks=" + result.getChecks() + " errors=" + result.getErrors());
    }

    // --------------------------------------------------------------------------- header rules

    /**
     * R-44. "The JWT MUST NOT use {@code none} as the signing algorithm". The signature segment is junk
     * rather than empty, so the credential gets past the compact-serialization check and it is this rule,
     * not that one, that refuses it. Other spellings never reach the rule — Keycloak's header parser
     * knows {@code alg} values case-sensitively and refuses them — but none of them verifies either.
     */
    @Test
    void theNoneAlgorithmIsRejected() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());
        assertRejected(verify(unsigned(did, "none")), "signingAlgorithmNotNone");
        for (String none : new String[]{"NONE", "None"}) {
            assertFalse(verify(unsigned(did, none)).isValid(), none);
        }
    }

    private static String unsigned(String did, String alg) throws Exception {
        Map<String, Object> header = header(methodId(did));
        header.put("alg", alg);
        return b64(JSON.writeValueAsBytes(header)) + "." + b64(JSON.writeValueAsBytes(SelfIssuedJwts.claims(did)))
                + "." + b64("junk".getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * R-44. RFC 7515 §4.1.11: a recipient that does not understand a header parameter named in
     * {@code crit} MUST reject the JWS. The credential is otherwise correctly signed, and the same one
     * without {@code crit} verifies.
     */
    @Test
    void aCriticalHeaderThisVerifierDoesNotImplementIsRejected() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());
        Map<String, Object> claims = SelfIssuedJwts.claims(did);

        assertValid(verify(sign(header(methodId(did)), claims, pair.getPrivate())));

        Map<String, Object> unencoded = header(methodId(did));
        unencoded.put("crit", List.of("b64"));
        unencoded.put("b64", true);
        assertRejected(verify(sign(unencoded, claims, pair.getPrivate())), "noUnsupportedCriticalHeaders");

        Map<String, Object> extension = header(methodId(did));
        extension.put("crit", List.of("urn:example:policy"));
        extension.put("urn:example:policy", "strict");
        assertRejected(verify(sign(extension, claims, pair.getPrivate())), "noUnsupportedCriticalHeaders");
    }

    // ---------------------------------------------------------------------------- claim rules

    /** A did:key credential with {@code edit} applied to otherwise valid claims. */
    private static SsiCidVerificationResult verifyClaims(java.util.function.Consumer<Map<String, Object>> edit)
            throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String did = DidKey.encodeEd25519(pair.getPublic());
        Map<String, Object> claims = SelfIssuedJwts.claims(did);
        edit.accept(claims);
        return verify(SelfIssuedJwts.sign(claims, "EdDSA", methodId(did), pair.getPrivate(), "Ed25519"));
    }

    /**
     * R-44. The credential MUST carry an {@code exp}: Keycloak reads a missing one as "never expires",
     * which would let a captured credential be replayed forever. Zero is no expiry either.
     */
    @Test
    void aCredentialWithoutAnExpiryIsRejected() throws Exception {
        SsiCidVerificationResult missing = verifyClaims(claims -> claims.remove("exp"));
        assertRejected(missing, "notExpired");
        assertTrue(missing.getErrors().toString().contains("'exp'"), missing.getErrors().toString());
        assertRejected(verifyClaims(claims -> claims.put("exp", 0)), "notExpired");
    }

    /** R-44. "The JWT MUST include an {@code iat} (issued at) claim." */
    @Test
    void aCredentialWithoutAnIssuedAtIsRejected() throws Exception {
        assertRejected(verifyClaims(claims -> claims.remove("iat")), "issuedAtPresent");
        assertRejected(verifyClaims(claims -> claims.put("iat", 0)), "issuedAtPresent");
    }

    /**
     * R-44. "The {@code aud} claim MUST include the target authorization server": a credential with no
     * {@code aud} at all names no target. (A blank one is pinned in SelfSignedCidDidSubjectTest.)
     */
    @Test
    void aCredentialWithoutAnAudienceIsRejected() throws Exception {
        assertRejected(verifyClaims(claims -> claims.remove("aud")), "audiencePresent");
    }

    /**
     * R-44. RFC 7519 §4.1.5: a JWT "MUST NOT be accepted for processing" before its {@code nbf}, less
     * the clock skew the server allows. One that became valid a moment ago verifies.
     */
    @Test
    void aCredentialThatIsNotYetValidIsRejected() throws Exception {
        long now = Instant.now().getEpochSecond();
        long skew = JwsChecks.clockSkewSeconds();
        assertRejected(verifyClaims(claims -> claims.put("nbf", now + skew + 120)), "notExpired");
        assertValid(verifyClaims(claims -> claims.put("nbf", now - 5)));
    }

    // ------------------------------------------------------------- an HTTPS subject's document

    private static final String SUB = "https://cid.example/alice";

    /** One answer from the subject's server, with the requests the verifier made recorded. */
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

    /**
     * A contextless CID document (CID 1.0 §4.2.1) for {@link #SUB} with one Multikey method per entry of
     * {@code methods} — fragment to extra JSON members — all holding {@code pair}'s public key.
     */
    private static String document(KeyPair pair, Map<String, String> methods) {
        String key = DidKey.multibaseValue(DidKey.encodeEd25519(pair.getPublic()));
        StringBuilder vms = new StringBuilder();
        StringBuilder auth = new StringBuilder();
        for (Map.Entry<String, String> method : methods.entrySet()) {
            if (vms.length() > 0) {
                vms.append(',');
                auth.append(',');
            }
            vms.append("{\"id\":\"").append(SUB).append('#').append(method.getKey())
                    .append("\",\"type\":\"Multikey\",\"controller\":\"").append(SUB)
                    .append("\",\"publicKeyMultibase\":\"").append(key).append('"').append(method.getValue()).append('}');
            auth.append('"').append(SUB).append('#').append(method.getKey()).append('"');
        }
        return "{\"id\":\"" + SUB + "\",\"verificationMethod\":[" + vms + "],\"authentication\":[" + auth + "]}";
    }

    private static String credential(KeyPair pair, String fragment) throws Exception {
        return SelfIssuedJwts.sign(SelfIssuedJwts.claims(SUB), "EdDSA", SUB + "#" + fragment, pair.getPrivate(), "Ed25519");
    }

    private static SsiCidVerificationResult verify(String jwt, Answer answer) {
        return new SelfSignedCidVerifier(null).fetchingWith(answer).verify(jwt, SelfIssuedJwts.AUDIENCE);
    }

    /**
     * R-44. CID 1.0 §2.2: a revoked method "MUST NOT be used", and a verifier is expected not to verify
     * a proof made with a method at or after its {@code expires}. Until now this was tested in the
     * collectors only; here the credential is otherwise valid, signed by the very key the method holds,
     * and a current method in the same document verifies.
     */
    @Test
    void aRevokedOrExpiredVerificationMethodIsRejected() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        Map<String, String> methods = new LinkedHashMap<>();
        methods.put("revoked", ",\"revoked\":\"2020-01-01T00:00:00Z\"");
        methods.put("expired", ",\"expires\":\"2021-06-01T00:00:00Z\"");
        methods.put("current", ",\"expires\":\"2999-01-01T00:00:00Z\"");
        String document = document(pair, methods);

        Answer answer = new Answer(200, "application/cid", document);
        assertValid(verify(credential(pair, "current"), answer));
        assertEquals(List.of(SUB + " | " + RdfParsing.ACCEPT + " | redirects=true"), answer.requests,
                "an HTTPS subject is dereferenced, redirects and all (R-29)");

        assertRejected(verify(credential(pair, "revoked"), new Answer(200, "application/cid", document)),
                "verificationMethodActive");
        assertRejected(verify(credential(pair, "expired"), new Answer(200, "application/cid", document)),
                "verificationMethodActive");
    }

    /**
     * R-44. Only a {@code 200} is a document. The body handed back here with each status is the
     * subject's real document — {@link OutboundHttp} never reads one, but the rule must not lean on that.
     */
    @Test
    void anHttpsSubjectThatDoesNotAnswer200IsNotDereferenced() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String document = document(pair, Map.of("k1", ""));
        assertValid(verify(credential(pair, "k1"), new Answer(200, "application/cid", document)));
        for (int status : new int[]{203, 204, 303, 404, 410, 500}) {
            SsiCidVerificationResult result = verify(credential(pair, "k1"), new Answer(status, "application/cid", document));
            assertRejected(result, "subjectDereferenced");
            assertEquals(null, result.getChecks().get("verificationMethodFound"), "nothing was read: " + status);
        }
    }

    /**
     * R-44. A document served as something that is not an RDF syntax this verifier reads is refused, and
     * the refusal names the media type the server chose — which is public, and actionable.
     */
    @Test
    void anHttpsSubjectServedAsAnUnreadableMediaTypeIsRefusedByName() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        String document = document(pair, Map.of("k1", ""));
        for (String type : new String[]{"text/html", "text/plain", "application/octet-stream"}) {
            SsiCidVerificationResult result = verify(credential(pair, "k1"), new Answer(200, type, document));
            assertRejected(result, "subjectDereferenced");
            assertTrue(result.getErrors().toString().contains("'" + type + "'"), result.getErrors().toString());
        }
    }

    /** R-44. A body that does not parse as the syntax it claims is no document. */
    @Test
    void anHttpsSubjectWhoseDocumentDoesNotParseIsNotDereferenced() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        assertRejected(verify(credential(pair, "k1"), new Answer(200, "application/cid", "{\"id\":")),
                "subjectDereferenced");
        assertRejected(verify(credential(pair, "k1"), new Answer(200, "text/turtle", "<" + SUB + "> <x")),
                "subjectDereferenced");
    }

    /**
     * R-44. A fetch that fails is reported as that, and never with its cause: the exception can name the
     * address the host resolved to, or this server's network, which the caller is not told.
     */
    @Test
    void aFailedFetchIsReportedWithoutItsCause() throws Exception {
        KeyPair pair = SelfIssuedJwts.ed25519();
        SsiCidVerificationResult result = verify(credential(pair, "k1"),
                new Answer(new IOException("Connect to 10.20.30.40:443 failed: Connection refused")));
        assertRejected(result, "subjectDereferenced");
        assertFalse(result.getErrors().toString().contains("10.20.30.40"), result.getErrors().toString());
    }
}
