package com.ebremer.lws.authn.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.Optional;

import org.junit.jupiter.api.Test;

/**
 * P3-3. A JWK {@code kid} is "a case-sensitive string" with no syntax at all (RFC 7517 §4.5), and the
 * self-signed CID document names each verification method {@code <subject>#<kid>}. Concatenated
 * unescaped, a {@code kid} with a space or a {@code #} in it is not an IRI, Jena refuses to serialize
 * it, and the endpoint answers 500 — for every key on that user, not just the badly-named one.
 */
class KeyIdFragmentTest {

    private static final String SUBJECT = "https://kc.example/realms/r/lws-ssi-cid/cid/u1";

    @Test
    void ordinaryKeyIdsAreLeftAlone() {
        assertEquals(Optional.of("k1"), KeyIdFragment.encode("k1"));
        assertEquals(Optional.of("2026-09-key.v2_final~1"), KeyIdFragment.encode("2026-09-key.v2_final~1"));
    }

    @Test
    void everythingElseIsPercentEncoded() {
        assertEquals(Optional.of("my%20key"), KeyIdFragment.encode("my key"));
        assertEquals(Optional.of("a%23b"), KeyIdFragment.encode("a#b"));
        assertEquals(Optional.of("a%2Fb%3Fc"), KeyIdFragment.encode("a/b?c"));
        assertEquals(Optional.of("%C3%A9"), KeyIdFragment.encode("é"));
    }

    /** The whole point: whatever comes out has to be an IRI Jena will actually write. */
    @Test
    void theResultingMethodIdIsAlwaysALegalIri() {
        for (String kid : new String[]{"k1", "my key", "a#b", "a/b?c", "é", "a\"b", "x<y>z", "tab\there",
                "back\\slash", "percent%already", "  spaced  "}) {
            String id = KeyIdFragment.methodId(SUBJECT, kid).orElseThrow();
            URI uri = URI.create(id);
            assertTrue(uri.isAbsolute(), "not a usable IRI for kid '" + kid + "': " + id);
            assertEquals(kid, KeyIdFragment.decode(uri.getRawFragment()),
                    "the fragment must still name the key it came from");
        }
    }

    @Test
    void aKeyIdThatCannotBeAFragmentIsRefusedRatherThanMangled() {
        assertTrue(KeyIdFragment.encode(null).isEmpty());
        assertTrue(KeyIdFragment.encode("").isEmpty());
        assertTrue(KeyIdFragment.encode("   ").isEmpty());
        assertTrue(KeyIdFragment.encode("k".repeat(KeyIdFragment.MAX_KID_LENGTH + 1)).isEmpty(),
                "an absurdly long kid should not become an absurdly long IRI");
        assertTrue(KeyIdFragment.encode("bad\uD800pair").isEmpty(),
                "an unpaired surrogate cannot be encoded without silently becoming a different string");
    }

    @Test
    void methodIdNeedsASubject() {
        assertTrue(KeyIdFragment.methodId(null, "k1").isEmpty());
        assertTrue(KeyIdFragment.methodId("", "k1").isEmpty());
        assertEquals(Optional.of(SUBJECT + "#k1"), KeyIdFragment.methodId(SUBJECT, "k1"));
    }

    /**
     * The decode side exists so the verifier can match a credential's {@code kid} against the fragment
     * of a method identifier — this provider's own, or another implementation's.
     */
    @Test
    void encodedFragmentsDecodeBackToTheKeyId() {
        for (String kid : new String[]{"k1", "my key", "a#b", "a/b?c", "é", "a+b"}) {
            assertEquals(kid, KeyIdFragment.decode(KeyIdFragment.encode(kid).orElseThrow()));
        }
    }

    /** A fragment that is not percent-encoded at all comes back untouched, including a literal '+'. */
    @Test
    void decodeLeavesUnencodedFragmentsAlone() {
        assertEquals("a+b", KeyIdFragment.decode("a+b"));
        assertEquals("plain", KeyIdFragment.decode("plain"));
        assertEquals("%zz", KeyIdFragment.decode("%zz"),
                "a malformed escape is returned as-is rather than throwing");
    }
}
