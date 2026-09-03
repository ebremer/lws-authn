/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Access control for the four credential-verification endpoints.
 */
package com.ebremer.lws.authn.verify;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * Decides whether a caller may use a {@code …/verify} endpoint, and at what rate.
 *
 * <p>Verification is an expensive, outward-facing operation: for the OpenID and self-signed-CID suites
 * a single POST makes this server dereference a URL the caller chose, perform OpenID Connect Discovery
 * against it and fetch its JWKS — all <em>before</em> the credential's signature is known to be good,
 * because that is the order the specification's cold-trust algorithm requires. Left open to anonymous
 * callers, that is request amplification, a network-probe oracle and a cheap denial of service.</p>
 *
 * <p>The endpoints are therefore authenticated by default. Modes:</p>
 * <ul>
 *   <li><b>{@code bearer}</b> (default) — the caller presents a Keycloak access token for this realm in
 *       {@code Authorization}. Optionally a realm role may be required.</li>
 *   <li><b>{@code secret}</b> — the caller presents a pre-shared secret as
 *       {@code Authorization: Bearer <secret>}. For verifiers that are not Keycloak clients.</li>
 *   <li><b>{@code public}</b> — no caller authentication, the pre-existing behaviour. Only for a
 *       deployment where the endpoints are already reachable solely from trusted networks.</li>
 * </ul>
 *
 * <p><strong>The {@code Authorization} header means different things in different modes.</strong> In
 * {@code bearer} and {@code secret} mode it carries the <em>caller's</em> credential, so the credential
 * being verified must be supplied as the {@code credential} form parameter. Only in {@code public} mode
 * does {@code Authorization: Bearer …} still fall back to meaning "the credential to verify", which is
 * what it has always meant — so {@code public} mode is exactly backwards compatible.</p>
 *
 * <p>Configuration is read from the provider's {@link Config.Scope} first, then a system property, then
 * an environment variable, so a deployment can configure it either through {@code kc.sh build} options
 * or through the environment alone:</p>
 * <table>
 *   <caption>Settings</caption>
 *   <tr><th>Scope key</th><th>System property</th><th>Environment</th><th>Default</th></tr>
 *   <tr><td>{@code access}</td><td>{@code lws.authn.verify.access}</td><td>{@code LWS_AUTHN_VERIFY_ACCESS}</td><td>{@code bearer}</td></tr>
 *   <tr><td>{@code secret}</td><td>{@code lws.authn.verify.secret}</td><td>{@code LWS_AUTHN_VERIFY_SECRET}</td><td>—</td></tr>
 *   <tr><td>{@code role}</td><td>{@code lws.authn.verify.role}</td><td>{@code LWS_AUTHN_VERIFY_ROLE}</td><td>—</td></tr>
 *   <tr><td>{@code rate-limit}</td><td>{@code lws.authn.verify.rateLimit}</td><td>{@code LWS_AUTHN_VERIFY_RATE_LIMIT}</td><td>{@code 60}</td></tr>
 * </table>
 *
 * @author Erich Bremer
 */
public final class VerifyAccess {

    private static final Logger log = Logger.getLogger(VerifyAccess.class);

    /** How a caller proves it may use a verify endpoint. */
    public enum Mode {
        /** A Keycloak access token for this realm. */
        BEARER,
        /** A pre-shared secret presented as a bearer token. */
        SECRET,
        /** No caller authentication (the pre-1.0 behaviour). */
        PUBLIC
    }

    private static final String BEARER_PREFIX = "Bearer ";
    private static final int DEFAULT_RATE_LIMIT = 60;

    private final Mode mode;
    private final byte[] secret;
    private final String requiredRole;
    private final RateLimiter limiter;

    private VerifyAccess(Mode mode, String secret, String requiredRole, int permitsPerMinute) {
        this.mode = mode;
        this.secret = secret == null ? null : secret.getBytes(StandardCharsets.UTF_8);
        this.requiredRole = requiredRole;
        this.limiter = permitsPerMinute > 0 ? new RateLimiter(permitsPerMinute) : null;
    }

    /**
     * Reads the policy for a provider. {@code scope} may be {@code null} (the factory was not given
     * one), in which case only the system-property and environment fallbacks apply.
     */
    public static VerifyAccess from(Config.Scope scope) {
        String access = setting(scope, "access", "lws.authn.verify.access", "LWS_AUTHN_VERIFY_ACCESS", "bearer");
        String secret = setting(scope, "secret", "lws.authn.verify.secret", "LWS_AUTHN_VERIFY_SECRET", null);
        String role = setting(scope, "role", "lws.authn.verify.role", "LWS_AUTHN_VERIFY_ROLE", null);
        String rate = setting(scope, "rate-limit", "lws.authn.verify.rateLimit", "LWS_AUTHN_VERIFY_RATE_LIMIT",
                String.valueOf(DEFAULT_RATE_LIMIT));

        Mode mode;
        try {
            mode = Mode.valueOf(access.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            log.warnf("Unknown lws-authn verify access mode '%s'; falling back to 'bearer'", access);
            mode = Mode.BEARER;
        }
        if (mode == Mode.SECRET && (secret == null || secret.isBlank())) {
            log.warn("lws-authn verify access mode is 'secret' but no secret is configured; "
                    + "falling back to 'bearer' rather than accepting every caller");
            mode = Mode.BEARER;
        }
        if (mode == Mode.PUBLIC) {
            log.warn("lws-authn verify endpoints are configured as PUBLIC: any anonymous caller can make this "
                    + "server dereference URLs of its choosing. Only do this on a trusted network.");
        }
        int permits;
        try {
            permits = Integer.parseInt(rate.trim());
        } catch (RuntimeException e) {
            permits = DEFAULT_RATE_LIMIT;
        }
        return new VerifyAccess(mode, secret, blankToNull(role), Math.max(0, permits));
    }

    /** The policy that applies when nothing is configured: bearer-authenticated and rate limited. */
    public static VerifyAccess defaults() {
        return from(null);
    }

    public Mode getMode() {
        return mode;
    }

    /**
     * Whether {@code Authorization: Bearer …} still means "the credential to verify". True only in
     * {@code public} mode; in every other mode that header carries the caller's own credential.
     */
    public boolean allowsCredentialInAuthorizationHeader() {
        return mode == Mode.PUBLIC;
    }

    /**
     * Checks whether this request may proceed.
     *
     * @return {@code null} when the caller is allowed, otherwise the response to return unchanged
     */
    public Response check(KeycloakSession session, String authorization) {
        if (limiter != null && !limiter.tryAcquire(callerKey(session))) {
            return error(Response.Status.TOO_MANY_REQUESTS, "slow_down",
                    "too many verification requests; retry shortly", session, false);
        }
        switch (mode) {
            case PUBLIC:
                return null;
            case SECRET: {
                String presented = bearerToken(authorization);
                byte[] offered = presented == null ? new byte[0] : presented.getBytes(StandardCharsets.UTF_8);
                if (secret == null || !MessageDigest.isEqual(secret, offered)) {
                    return error(Response.Status.UNAUTHORIZED, "invalid_token",
                            "a valid shared secret is required", session, true);
                }
                return null;
            }
            case BEARER:
            default: {
                AuthenticationManager.AuthResult auth =
                        new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
                if (auth == null) {
                    return error(Response.Status.UNAUTHORIZED, "invalid_token",
                            "a valid access token for this realm is required", session, true);
                }
                if (requiredRole != null && !hasRealmRole(auth.token(), requiredRole)) {
                    return error(Response.Status.FORBIDDEN, "insufficient_scope",
                            "the '" + requiredRole + "' realm role is required", session, true);
                }
                return null;
            }
        }
    }

    /** The bearer value of an {@code Authorization} header, or {@code null} when there is not one. */
    public static String bearerToken(String authorization) {
        if (authorization == null || !authorization.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return null;
        }
        String value = authorization.substring(BEARER_PREFIX.length()).trim();
        return value.isEmpty() ? null : value;
    }

    // --------------------------------------------------------------------------------- internals

    private static boolean hasRealmRole(AccessToken token, String role) {
        return token != null && token.getRealmAccess() != null && token.getRealmAccess().isUserInRole(role);
    }

    /**
     * Builds the denial. A 401 or 403 carries {@code WWW-Authenticate} as RFC 9110 §15.5.2 requires,
     * which also lets a client tell "you are not allowed to call this endpoint" apart from "the
     * credential you asked me to check is invalid" — the two are otherwise both 401 here.
     */
    private Response error(Response.Status status, String code, String description,
                           KeycloakSession session, boolean challenge) {
        Response.ResponseBuilder response = Response.status(status)
                .entity("{\"error\":\"" + code + "\",\"error_description\":\"" + description + "\"}")
                .type(MediaType.APPLICATION_JSON);
        if (challenge) {
            response.header("WWW-Authenticate", "Bearer realm=\"" + realmName(session) + "\", error=\"" + code
                    + "\", error_description=\"" + description + "\"");
        }
        return response.build();
    }

    private static String realmName(KeycloakSession session) {
        try {
            RealmModel realm = session.getContext().getRealm();
            return realm == null ? "lws" : realm.getName();
        } catch (RuntimeException e) {
            return "lws";
        }
    }

    private static String callerKey(KeycloakSession session) {
        try {
            String remote = session.getContext().getConnection() == null
                    ? null : session.getContext().getConnection().getRemoteAddr();
            return remote == null || remote.isBlank() ? "unknown" : remote;
        } catch (RuntimeException e) {
            return "unknown";
        }
    }

    private static String setting(Config.Scope scope, String scopeKey, String systemProperty,
                                  String environmentVariable, String fallback) {
        if (scope != null) {
            String value = scope.get(scopeKey);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        String value = System.getProperty(systemProperty);
        if (value == null || value.isBlank()) {
            value = System.getenv(environmentVariable);
        }
        return value == null || value.isBlank() ? fallback : value;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
