/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * P0-3. The endpoints must be closed by default, and a misconfiguration must never fail open.
 */
class VerifyAccessTest {

    @Test
    void defaultsToRequiringABearerToken() {
        assertEquals(VerifyAccess.Mode.BEARER, VerifyAccess.defaults().getMode(),
                "an unconfigured deployment must not expose an anonymous verification oracle");
    }

    /**
     * In bearer/secret mode the Authorization header carries the caller's own credential, so it must
     * not double as the credential under test; only the historical public mode keeps that fallback.
     */
    @Test
    void authorizationHeaderIsTheCredentialOnlyWhenPublic() {
        assertFalse(VerifyAccess.defaults().allowsCredentialInAuthorizationHeader());
        assertTrue(withProperty("lws.authn.verify.access", "public",
                () -> VerifyAccess.defaults().allowsCredentialInAuthorizationHeader()));
    }

    @Test
    void publicModeIsOptIn() {
        assertEquals(VerifyAccess.Mode.PUBLIC,
                withProperty("lws.authn.verify.access", "public", () -> VerifyAccess.defaults().getMode()));
        assertEquals(VerifyAccess.Mode.PUBLIC,
                withProperty("lws.authn.verify.access", "PUBLIC", () -> VerifyAccess.defaults().getMode()));
    }

    /** An unreadable mode must fall back to the closed default, never to the open one. */
    @Test
    void anUnknownModeFailsClosed() {
        assertEquals(VerifyAccess.Mode.BEARER,
                withProperty("lws.authn.verify.access", "wide-open", () -> VerifyAccess.defaults().getMode()));
    }

    /** Secret mode with no secret configured would accept every caller; it must not be honoured. */
    @Test
    void secretModeWithoutASecretFailsClosed() {
        assertEquals(VerifyAccess.Mode.BEARER,
                withProperty("lws.authn.verify.access", "secret", () -> VerifyAccess.defaults().getMode()));
    }

    @Test
    void secretModeIsHonouredWhenASecretIsConfigured() {
        assertEquals(VerifyAccess.Mode.SECRET, withProperty("lws.authn.verify.access", "secret",
                () -> withProperty("lws.authn.verify.secret", "s3cr3t", () -> VerifyAccess.defaults().getMode())));
    }

    @Test
    void readsTheBearerValueOfAnAuthorizationHeader() {
        assertEquals("abc", VerifyAccess.bearerToken("Bearer abc"));
        assertEquals("abc", VerifyAccess.bearerToken("bearer abc"), "the scheme is case-insensitive");
        assertNull(VerifyAccess.bearerToken("Basic abc"));
        assertNull(VerifyAccess.bearerToken("Bearer   "));
        assertNull(VerifyAccess.bearerToken(null));
    }

    // ------------------------------------------------------------------------------------ helpers

    private static <T> T withProperty(String key, String value, java.util.function.Supplier<T> body) {
        String previous = System.getProperty(key);
        System.setProperty(key, value);
        try {
            return body.get();
        } finally {
            if (previous == null) {
                System.clearProperty(key);
            } else {
                System.setProperty(key, previous);
            }
        }
    }
}
