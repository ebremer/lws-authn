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

import java.lang.reflect.Proxy;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

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

    /** R-09. A credential is a few kilobytes; one far longer is only work for the parsers. */
    @Test
    void refusesAnOversizedCredential() {
        assertNull(VerifyAccess.refuseOversized("x".repeat(VerifyAccess.MAX_CREDENTIAL_LENGTH)));
        assertNull(VerifyAccess.refuseOversized(null));
        assertEquals(400, VerifyAccess.refuseOversized("x".repeat(VerifyAccess.MAX_CREDENTIAL_LENGTH + 1)).getStatus());
    }

    /** R-10. One subscriber is routinely given a whole /64; it is one caller, not 2^64 of them. */
    @Test
    void bucketsAnIpv6CallerByItsSlash64() {
        assertEquals("2001:db8:1:2:0:0:0:0/64", VerifyAccess.addressKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd"));
        assertEquals(VerifyAccess.addressKey("2001:db8:1:2::1"), VerifyAccess.addressKey("[2001:db8:1:2:ffff::9]"));
        assertEquals(VerifyAccess.addressKey("fe80::1"), VerifyAccess.addressKey("fe80::2%eth0"));
        assertFalse(VerifyAccess.addressKey("2001:db8:1:2::1").equals(VerifyAccess.addressKey("2001:db8:1:3::1")));
    }

    @Test
    void keepsIpv4AndAnythingElseAsItIs() {
        assertEquals("203.0.113.7", VerifyAccess.addressKey("203.0.113.7"));
        assertEquals("203.0.113.7", VerifyAccess.addressKey("::ffff:203.0.113.7"), "an IPv4-mapped address is its IPv4 address");
        assertEquals("evil.example:80", VerifyAccess.addressKey("evil.example:80"), "not a literal: kept, never resolved");
        assertEquals("not-an-address", VerifyAccess.addressKey("not-an-address"));
    }

    @Test
    void aUsersBucketIsApartFromEveryAddresss() {
        assertFalse(VerifyAccess.principalKey("203.0.113.7").equals(VerifyAccess.addressKey("203.0.113.7")));
    }

    /**
     * R-11. A verify endpoint is called by an authorization server, not by every user of the realm: the
     * default requires a role, and admitting any user is a choice that has to be spelled out.
     */
    @Test
    void requiresTheVerifierRoleByDefault() {
        assertEquals(VerifyAccess.DEFAULT_ROLE, VerifyAccess.defaults().getRequiredRole());
        assertEquals("auditor", withProperty("lws.authn.verify.role", "auditor",
                () -> VerifyAccess.defaults().getRequiredRole()));
        assertNull(withProperty("lws.authn.verify.role", "*", () -> VerifyAccess.defaults().getRequiredRole()),
                "'*' is the explicit opt-out");
    }

    /** R-11. What counts is whether the user holds the role now, not what a token said when it was issued. */
    @Test
    void theRoleMustStillBeHeld() {
        RoleModel role = role("lws-verifier");
        assertTrue(VerifyAccess.holdsRole(user(role), role));
        assertFalse(VerifyAccess.holdsRole(user(), role), "taken away since the token was issued");
        assertFalse(VerifyAccess.holdsRole(user(role("something-else")), role));
        assertFalse(VerifyAccess.holdsRole(user(role), null), "the realm defines no such role");
        assertFalse(VerifyAccess.holdsRole(null, role));
    }

    private static RoleModel role(String name) {
        return (RoleModel) Proxy.newProxyInstance(RoleModel.class.getClassLoader(), new Class<?>[]{RoleModel.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "getName" -> name;
                    case "hashCode" -> name.hashCode();
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    /** A user holding exactly {@code held}. */
    private static UserModel user(RoleModel... held) {
        Set<RoleModel> roles = Set.of(held);
        return (UserModel) Proxy.newProxyInstance(UserModel.class.getClassLoader(), new Class<?>[]{UserModel.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "hasRole" -> roles.contains(args[0]);
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    /**
     * R-36. RFC 6750 §3.1: with no credential in the request, the challenge "SHOULD NOT include an error
     * code or other error information"; and §3 limits {@code error_description} to printable ASCII
     * without {@code "} or {@code \\}, which a configured role name need not be.
     */
    @Test
    void theChallengeSaysOnlyWhatRfc6750Allows() {
        assertEquals("Bearer realm=\"demo\"", VerifyAccess.challenge("demo", null, "a token is required"));
        assertEquals("Bearer realm=\"de\\\"mo\", error=\"insufficient_scope\", "
                        + "error_description=\"the '?quoted??' r?le is required\"",
                VerifyAccess.challenge("de\"mo", "insufficient_scope", "the '\"quoted\\\"' r\u00f4le is required"));
    }
}
