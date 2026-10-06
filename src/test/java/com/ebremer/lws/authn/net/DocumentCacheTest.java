/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

/** R-26: how long a fetched document may be reused, and how much of them is kept. */
class DocumentCacheTest {

    private static OutboundHttp.Fetched document(String body) {
        return new OutboundHttp.Fetched(200, "text/turtle", body, true);
    }

    /** RFC 9111, read as a shared cache: the verifier answers many callers from one copy. */
    @Test
    void cacheControlCanShortenOrForbidButNeverLengthen() {
        assertEquals(300, DocumentCache.freshnessSeconds(null, 300), "no directives: the ceiling");
        assertEquals(300, DocumentCache.freshnessSeconds("public", 300));
        assertEquals(60, DocumentCache.freshnessSeconds("public, max-age=60", 300));
        assertEquals(300, DocumentCache.freshnessSeconds("max-age=86400", 300), "never past the ceiling");
        assertEquals(10, DocumentCache.freshnessSeconds("max-age=600, s-maxage=10", 300), "s-maxage wins");
        assertEquals(0, DocumentCache.freshnessSeconds("max-age=0", 300));
        for (String forbidden : new String[]{"no-store", "no-cache", "private, max-age=600", "max-age=600, No-Store"}) {
            assertEquals(0, DocumentCache.freshnessSeconds(forbidden, 300), forbidden);
        }
        assertEquals(0, DocumentCache.freshnessSeconds("max-age=soon", 300), "unreadable is not a licence");
        assertEquals(0, DocumentCache.freshnessSeconds("max-age=60", 0), "a ceiling of 0 is caching off");
    }

    @Test
    void aDocumentIsServedUntilItExpires() {
        DocumentCache cache = new DocumentCache();
        cache.put("k", document("body"), 1_000, 5_000);
        assertNotNull(cache.get("k", 5_999));
        assertNull(cache.get("k", 6_000));
        assertEquals(0, cache.size(), "an expired entry is dropped when found");
        cache.put("k", document("body"), 1_000, 0);
        assertNull(cache.get("k", 1_000), "a lifetime of 0 stores nothing");
    }

    /** A caller naming a new URL every time can churn the cache, not grow it. */
    @Test
    void theCacheIsBoundedInEntriesAndInSize() {
        DocumentCache cache = new DocumentCache();
        for (int i = 0; i <= DocumentCache.MAX_ENTRIES; i++) {
            cache.put("k" + i, document("x"), 0, 60_000);
        }
        assertEquals(DocumentCache.MAX_ENTRIES, cache.size());
        assertNull(cache.get("k0", 1), "least recently used goes first");

        DocumentCache bySize = new DocumentCache();
        String large = "x".repeat((int) (DocumentCache.MAX_CHARS / 4));
        for (int i = 0; i < 5; i++) {
            bySize.put("k" + i, document(large), 0, 60_000);
        }
        assertEquals(4, bySize.size());
        assertNull(bySize.get("k0", 1));
        assertNotNull(bySize.get("k4", 1));
    }
}
