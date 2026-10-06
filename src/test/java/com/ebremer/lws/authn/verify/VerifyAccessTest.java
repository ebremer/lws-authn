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

import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.Test;
import org.keycloak.common.ClientConnection;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
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

    // ------------------------------------------------------- the decision itself (R-44)

    /**
     * R-44. {@code secret} mode admits the configured secret and nothing else \u2014 not another value, not a
     * prefix or an extension of it, not the secret under another scheme \u2014 and every refusal is a
     * {@code 401} with a challenge. Until now only the parsing around it was tested.
     */
    @Test
    void secretModeAdmitsTheSecretAndNothingElse() throws Exception {
        VerifyAccess access = withProperties(() -> VerifyAccess.defaults(),
                "lws.authn.verify.access", "secret", "lws.authn.verify.secret", "s3cr3t",
                "lws.authn.verify.rateLimit", "0");
        KeycloakSession session = session("203.0.113.7", realm("demo", null));
        assertNull(access.check(session, "Bearer s3cr3t"));
        assertNull(access.check(session, "bearer s3cr3t"), "the scheme is case-insensitive");

        for (String wrong : new String[]{"Bearer wrong", "Bearer s3cr3", "Bearer s3cr3t-and-more", "Bearer S3CR3T"}) {
            Response refused = access.check(session, wrong);
            assertEquals(401, refused.getStatus(), wrong);
            assertEquals("invalid_token", errorOf(refused), wrong);
            assertEquals("Bearer realm=\"demo\", error=\"invalid_token\", "
                    + "error_description=\"a valid shared secret is required\"",
                    refused.getHeaderString("WWW-Authenticate"), wrong);
        }
        // No bearer credential at all: still a 401, with the bare challenge of RFC 6750 \u00a73.1 (R-36).
        for (String absent : new String[]{null, "", "Basic czNjcjN0", "s3cr3t"}) {
            Response refused = access.check(session, absent);
            assertEquals(401, refused.getStatus(), String.valueOf(absent));
            assertEquals("Bearer realm=\"demo\"", refused.getHeaderString("WWW-Authenticate"), String.valueOf(absent));
        }
    }

    /**
     * R-44. A caller over its rate is told {@code 429 slow_down} with {@code Retry-After} (R-36), and
     * <em>without</em> a {@code WWW-Authenticate} challenge: its credential was not the problem, and a
     * challenge would send a client off to fetch a new token it does not need. The bucket is the
     * caller's, so another caller is unaffected.
     */
    @Test
    void aCallerOverItsRateIsToldToSlowDownWithoutAChallenge() throws Exception {
        VerifyAccess access = withProperties(() -> VerifyAccess.defaults(),
                "lws.authn.verify.access", "public", "lws.authn.verify.rateLimit", "1");
        KeycloakSession caller = session("203.0.113.8", realm("demo", null));
        assertNull(access.check(caller, null));
        Response limited = access.check(caller, null);
        assertEquals(429, limited.getStatus());
        assertEquals("slow_down", errorOf(limited));
        assertNull(limited.getHeaderString("WWW-Authenticate"), "a rate limit is not an authentication failure");
        assertTrue(Long.parseLong(limited.getHeaderString("Retry-After")) >= 1);
        assertNull(access.check(session("203.0.113.9", realm("demo", null)), null), "another caller's bucket is its own");
    }

    /**
     * R-44. In {@code bearer} mode, an authenticated user who does not hold the required role \u2014 or whose
     * realm does not define it \u2014 is refused with {@code 403 insufficient_scope} and a challenge saying
     * so (RFC 6750 \u00a73.1); a user who holds it, or any user when {@code role=*}, is admitted.
     */
    @Test
    void aUserWithoutTheRoleIsRefusedWithInsufficientScope() throws Exception {
        RoleModel verifier = role(VerifyAccess.DEFAULT_ROLE);
        KeycloakSession session = session("203.0.113.10", realm("demo", verifier));
        VerifyAccess access = withProperties(() -> VerifyAccess.defaults(), "lws.authn.verify.rateLimit", "0");

        assertNull(access.checkAuthenticated(session, user("u1", verifier)));

        Response refused = access.checkAuthenticated(session, user("u2"));
        assertEquals(403, refused.getStatus());
        assertEquals("insufficient_scope", errorOf(refused));
        assertEquals("Bearer realm=\"demo\", error=\"insufficient_scope\", "
                + "error_description=\"the 'lws-verifier' realm role is required\"",
                refused.getHeaderString("WWW-Authenticate"));

        Response undefined = access.checkAuthenticated(session("203.0.113.10", realm("other", null)), user("u1", verifier));
        assertEquals(403, undefined.getStatus(), "a role the realm does not define is held by nobody");

        VerifyAccess anyUser = withProperties(() -> VerifyAccess.defaults(),
                "lws.authn.verify.role", "*", "lws.authn.verify.rateLimit", "0");
        assertNull(anyUser.checkAuthenticated(session, user("u2")), "role=* admits any user of the realm");
    }

    /**
     * R-44 (R-10). An authenticated user has a bucket of their own, which a change of address does not
     * escape: behind a proxy that passes on a client's {@code X-Forwarded-For}, every request could
     * otherwise claim a fresh one.
     */
    @Test
    void anAuthenticatedUsersBucketFollowsTheUserNotTheAddress() throws Exception {
        RoleModel verifier = role(VerifyAccess.DEFAULT_ROLE);
        VerifyAccess access = withProperties(() -> VerifyAccess.defaults(), "lws.authn.verify.rateLimit", "1");
        UserModel user = user("u3", verifier);
        assertNull(access.checkAuthenticated(session("203.0.113.11", realm("demo", verifier)), user));
        Response limited = access.checkAuthenticated(session("198.51.100.12", realm("demo", verifier)), user);
        assertEquals(429, limited.getStatus());
        assertEquals("slow_down", errorOf(limited));
        assertNull(limited.getHeaderString("WWW-Authenticate"));
        assertNull(access.checkAuthenticated(session("198.51.100.12", realm("demo", verifier)), user("u4", verifier)),
                "another user's bucket is their own");
    }

    // ------------------------------------------------------------------------------- fakes

    /** Sets each key to its value for the length of {@code body}, then restores what was there. */
    private static <T> T withProperties(java.util.function.Supplier<T> body, String... keysAndValues) {
        if (keysAndValues.length == 0) {
            return body.get();
        }
        String[] rest = java.util.Arrays.copyOfRange(keysAndValues, 2, keysAndValues.length);
        return withProperty(keysAndValues[0], keysAndValues[1], () -> withProperties(body, rest));
    }

    private static String errorOf(Response response) throws Exception {
        return new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(String.valueOf(response.getEntity())).path("error").asText();
    }

    /** A session whose caller is at {@code address}, in {@code realm}; nothing else may be asked of it. */
    private static KeycloakSession session(String address, RealmModel realm) {
        ClientConnection connection = fake(ClientConnection.class, (method, args) -> switch (method) {
            case "getRemoteAddr", "getRemoteHost" -> address;
            default -> null;
        });
        KeycloakContext context = fake(KeycloakContext.class, (method, args) -> switch (method) {
            case "getConnection" -> connection;
            case "getRealm" -> realm;
            default -> throw new UnsupportedOperationException("KeycloakContext." + method);
        });
        return fake(KeycloakSession.class, (method, args) -> switch (method) {
            case "getContext" -> context;
            default -> throw new UnsupportedOperationException("KeycloakSession." + method);
        });
    }

    /** A realm named {@code name} defining at most one role, {@code defined}. */
    private static RealmModel realm(String name, RoleModel defined) {
        return fake(RealmModel.class, (method, args) -> switch (method) {
            case "getName" -> name;
            case "getId" -> name + "-id";
            case "getRole" -> defined != null && defined.getName().equals(args[0]) ? defined : null;
            default -> throw new UnsupportedOperationException("RealmModel." + method);
        });
    }

    /** A user with id {@code id} holding exactly {@code held}. */
    private static UserModel user(String id, RoleModel... held) {
        Set<RoleModel> roles = Set.of(held);
        return fake(UserModel.class, (method, args) -> switch (method) {
            case "getId" -> id;
            case "hasRole" -> roles.contains(args[0]);
            default -> throw new UnsupportedOperationException("UserModel." + method);
        });
    }

    private interface Answers {
        Object answer(String method, Object[] args);
    }

    private static <T> T fake(Class<T> type, Answers answers) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (proxy, method, args) -> switch (method.getName()) {
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    case "toString" -> type.getSimpleName() + "@fake";
                    default -> answers.answer(method.getName(), args);
                }));
    }
}
