/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * A small, bounded cache of the documents the verifiers fetch.
 */
package com.ebremer.lws.authn.net;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Remembers successful fetches for as long as their server allows, up to a ceiling (R-26).
 *
 * <p>Both JWT suites' privacy sections: "Verifiers are encouraged to cache controlled identifier
 * documents to reduce unnecessary network requests and the associated metadata leakage." Without a
 * cache every OpenID verification made three requests and every self-signed one made one, each telling
 * the subject's host that someone was verifying the subject, and each holding a worker thread.</p>
 *
 * <p>Bounded twice — in entries and in characters held — and least-recently-used first out, so a caller
 * naming a new URL with every request can churn the cache but not grow it. Only a {@code 200} is
 * stored; a failure is asked again, so a server that recovers is noticed at once. Only documents are
 * stored, never a verdict: each verification still checks the signature, the claims and the time
 * against what the document says.</p>
 *
 * @author Erich Bremer
 */
final class DocumentCache {

    /** Most documents held at once. */
    static final int MAX_ENTRIES = 1024;

    /** Most characters of document held at once: 16 Mi, a few dozen times the largest one allowed. */
    static final long MAX_CHARS = 16L * 1024 * 1024;

    private record Entry(OutboundHttp.Fetched fetched, long fetchedAt, long expiresAt) {
        long size() {
            return fetched.body() == null ? 0 : fetched.body().length();
        }
    }

    private final LinkedHashMap<String, Entry> entries = new LinkedHashMap<>(64, 0.75f, true);
    private long chars;

    /** The document stored under {@code key}, if it is still fresh at {@code now}. */
    synchronized OutboundHttp.Fetched get(String key, long now) {
        Entry entry = entries.get(key);
        if (entry == null) {
            return null;
        }
        if (now >= entry.expiresAt()) {
            remove(key);
            return null;
        }
        return entry.fetched();
    }

    /** When the document under {@code key} was fetched, or {@code -1} if none is held. */
    synchronized long fetchedAt(String key) {
        Entry entry = entries.get(key);
        return entry == null ? -1 : entry.fetchedAt();
    }

    /** Stores {@code fetched} under {@code key} for {@code ttlMillis}; nothing if that is not positive. */
    synchronized void put(String key, OutboundHttp.Fetched fetched, long now, long ttlMillis) {
        remove(key);
        if (ttlMillis <= 0) {
            return;
        }
        Entry entry = new Entry(fetched, now, now + ttlMillis);
        if (entry.size() > MAX_CHARS) {
            return;
        }
        entries.put(key, entry);
        chars += entry.size();
        Iterator<Map.Entry<String, Entry>> eldest = entries.entrySet().iterator();
        while ((entries.size() > MAX_ENTRIES || chars > MAX_CHARS) && eldest.hasNext()) {
            chars -= eldest.next().getValue().size();
            eldest.remove();
        }
    }

    synchronized void clear() {
        entries.clear();
        chars = 0;
    }

    synchronized int size() {
        return entries.size();
    }

    private void remove(String key) {
        Entry old = entries.remove(key);
        if (old != null) {
            chars -= old.size();
        }
    }

    /**
     * How long a response may be reused, in seconds, given its {@code Cache-Control} and this server's
     * {@code ceiling}: RFC 9111 as a shared cache reads it — the verifier answers many callers from one
     * copy. {@code no-store}, {@code no-cache} and {@code private} forbid it; {@code s-maxage} wins over
     * {@code max-age}; a value that will not parse forbids it too. With no lifetime given, the ceiling
     * applies — heuristic freshness, which RFC 9111 §4.2.2 allows a cache to assign.
     */
    static long freshnessSeconds(String cacheControl, long ceiling) {
        if (ceiling <= 0) {
            return 0;
        }
        if (cacheControl == null || cacheControl.isBlank()) {
            return ceiling;
        }
        Long maxAge = null;
        Long sharedMaxAge = null;
        for (String part : cacheControl.toLowerCase(Locale.ROOT).split(",")) {
            String directive = part.trim();
            String name = directive.contains("=") ? directive.substring(0, directive.indexOf('=')).trim() : directive;
            String value = directive.contains("=")
                    ? directive.substring(directive.indexOf('=') + 1).trim().replace("\"", "") : null;
            switch (name) {
                case "no-store", "no-cache", "private" -> {
                    return 0;
                }
                case "max-age" -> maxAge = seconds(value);
                case "s-maxage" -> sharedMaxAge = seconds(value);
                default -> {
                    // public, must-revalidate, immutable … say nothing about how long
                }
            }
        }
        Long lifetime = sharedMaxAge != null ? sharedMaxAge : maxAge;
        return lifetime == null ? ceiling : Math.max(0, Math.min(lifetime, ceiling));
    }

    private static long seconds(String value) {
        try {
            return value == null ? 0 : Long.parseLong(value);
        } catch (NumberFormatException unreadable) {
            return 0;
        }
    }
}
