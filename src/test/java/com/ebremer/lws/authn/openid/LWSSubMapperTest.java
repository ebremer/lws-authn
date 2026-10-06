/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.openid;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.representations.userprofile.config.UPAttributePermissions;
import org.keycloak.representations.userprofile.config.UPConfig;
import org.keycloak.userprofile.UserProfileProvider;

/**
 * R-05. The WebID goes into the ID Token — the LWS credential — and not into the access token unless
 * someone asks for it. An access token with a WebID {@code sub} carries everything an LWS verifier that
 * does not check the token's type looks at, so a party the user handed it to could present it as the
 * user's credential.
 *
 * <p>R-30. A WebID attribute is used only if it can be this user's subject and nobody else's.</p>
 */
class LWSSubMapperTest {

    private static final String ISSUER = "https://id.example/realms/demo";
    private static final String ALICE = "8f3c1e2a-0000-4000-8000-000000000000";
    private static final String BOB = "1d7b9c40-0000-4000-8000-000000000000";
    private static final String HOSTED = ISSUER + "/lws/cid/" + ALICE;

    private static String defaultOf(String name) {
        return new LWSSubMapper().getConfigProperties().stream()
                .filter(p -> p.getName().equals(name))
                .map(ProviderConfigProperty::getDefaultValue)
                .map(String::valueOf)
                .findFirst().orElseThrow();
    }

    @Test
    void offersTheWebIdForTheIdTokenButNotTheAccessToken() {
        assertEquals("true", defaultOf(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN));
        assertEquals("false", defaultOf(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN));
        // Userinfo follows the ID Token; there is no switch to make them differ.
        assertTrue(new LWSSubMapper().getConfigProperties().stream()
                .noneMatch(p -> p.getName().equals(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO)));
    }

    /**
     * A mapper whose configuration never mentions the access token — created over the admin API with
     * only the attribute set — leaves the access token's subject alone. It used to treat "not set" as
     * "on".
     */
    @Test
    void leavesTheAccessTokenAloneUnlessToldOtherwise() {
        for (Map<String, String> config : java.util.List.of(
                new HashMap<String, String>(),
                new HashMap<>(Map.of(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "false")))) {
            ProtocolMapperModel model = new ProtocolMapperModel();
            model.setConfig(config);
            AccessToken token = new AccessToken();
            token.subject(ALICE);
            // With the access token excluded the mapper never reaches the session, so none is needed.
            new LWSSubMapper().transformAccessToken(token, model, null, null, null);
            assertEquals(ALICE, token.getSubject(), config.toString());
        }
    }

    // ---------------------------------------------------------------------------------- R-30

    private static RealmModel realm() {
        return (RealmModel) Proxy.newProxyInstance(LWSSubMapperTest.class.getClassLoader(),
                new Class<?>[]{RealmModel.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getId" -> "realm-id";
                    case "getName" -> "demo";
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static UserModel user(String id, String webId) {
        return (UserModel) Proxy.newProxyInstance(LWSSubMapperTest.class.getClassLoader(),
                new Class<?>[]{UserModel.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getId" -> id;
                    case "getFirstAttribute" -> "lws_webid".equals(args[0]) ? webId : null;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    /** A session whose realm holds {@code holders} — the users the attribute search finds — and a profile. */
    private static KeycloakSession session(List<UserModel> holders, UserProfileProvider profile) {
        UserProvider users = (UserProvider) Proxy.newProxyInstance(LWSSubMapperTest.class.getClassLoader(),
                new Class<?>[]{UserProvider.class}, (proxy, method, args) -> {
                    if ("searchForUserByUserAttributeStream".equals(method.getName())) {
                        return holders.stream().filter(u -> args[2].equals(u.getFirstAttribute("lws_webid")));
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
        return (KeycloakSession) Proxy.newProxyInstance(LWSSubMapperTest.class.getClassLoader(),
                new Class<?>[]{KeycloakSession.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "users" -> users;
                    case "getProvider" -> profile;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static UserSessionModel userSession(UserModel user) {
        RealmModel realm = realm();
        return (UserSessionModel) Proxy.newProxyInstance(LWSSubMapperTest.class.getClassLoader(),
                new Class<?>[]{UserSessionModel.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "getUser" -> user;
                    case "getRealm" -> realm;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static ProtocolMapperModel mapper(Map<String, String> extra) {
        Map<String, String> config = new HashMap<>(Map.of(LWSSubMapper.WEBID_ATTRIBUTE, "lws_webid"));
        config.putAll(extra);
        ProtocolMapperModel model = new ProtocolMapperModel();
        model.setConfig(config);
        return model;
    }

    /** The ID Token's {@code sub} for {@code user}, with {@code others} also in the realm. */
    private static String subjectOf(UserModel user, UserModel... others) {
        List<UserModel> everyone = new java.util.ArrayList<>(List.of(others));
        everyone.add(user);
        IDToken token = new IDToken();
        token.issuer(ISSUER);
        new LWSSubMapper().transformIDToken(token, mapper(Map.of()), session(everyone, null), userSession(user), null);
        return token.getSubject();
    }

    @Test
    void aWebIdTheUserAloneHoldsIsTheirSubject() {
        assertEquals("https://alice.example/profile#me", subjectOf(user(ALICE, " https://alice.example/profile#me ")));
        assertEquals(HOSTED, subjectOf(user(ALICE, null)));
        assertEquals(HOSTED, subjectOf(user(ALICE, HOSTED)), "naming one's own hosted WebID is harmless");
    }

    /**
     * Another user's hosted document lists this issuer as that user's OpenID provider, so a token naming
     * it verified as that user. Only an admin-only attribute policy stood in the way.
     */
    @Test
    void anotherUsersHostedDocumentIsNotASubject() {
        for (String victim : new String[]{
                ISSUER + "/lws/cid/" + BOB,
                "https://ID.example:443/realms/demo/lws/cid/" + BOB,
                ISSUER + "/lws/cid/../cid/" + BOB,
                ISSUER + "/lws-ssi-cid/cid/" + BOB,
                ISSUER}) {
            assertEquals(HOSTED, subjectOf(user(ALICE, victim)), victim);
        }
        // Another realm, or a lookalike path, is somebody else's namespace.
        assertNull(LWSSubMapper.problem("https://id.example/realms/demo2/lws/cid/" + BOB, ISSUER, HOSTED));
        assertNull(LWSSubMapper.problem("https://id.example:8443/realms/demo/lws/cid/" + BOB, ISSUER, HOSTED));
    }

    /** OIDC Core §2: a {@code sub} is locally unique. Two holders of one WebID would be one subject. */
    @Test
    void aWebIdTwoUsersHoldIsNeithersSubject() {
        String shared = "https://shared.example/profile#me";
        assertEquals(HOSTED, subjectOf(user(ALICE, shared), user(BOB, shared)));
        assertEquals("https://alice.example/profile#me",
                subjectOf(user(ALICE, "https://alice.example/profile#me"), user(BOB, shared)));
    }

    /** OIDC Core §2: "It MUST NOT exceed 255 ASCII characters in length." */
    @Test
    void aWebIdMustBeAtMost255AsciiCharacters() {
        String longest = "https://alice.example/" + "a".repeat(255 - "https://alice.example/".length());
        assertEquals(longest, subjectOf(user(ALICE, longest)));
        assertEquals(HOSTED, subjectOf(user(ALICE, longest + "a")));
        assertEquals(HOSTED, subjectOf(user(ALICE, "https://alice.example/prófile")));
        assertEquals(HOSTED, subjectOf(user(ALICE, "urn:uuid:" + ALICE)));
    }

    /** A user-storage id may hold anything; it is one path segment of the WebID, encoded as one. */
    @Test
    void theUserIdIsEncodedAsOnePathSegment() {
        assertEquals(ISSUER + "/lws/cid/f:4b1e:alice%2Fadmin%23x%20y%C3%A9",
                subjectOf(user("f:4b1e:alice/admin#x yé", null)));
    }

    /** OIDC Core §5.3.2: userinfo's {@code sub} MUST match the ID Token's, so it follows that switch. */
    @Test
    void userinfoFollowsTheIdTokenSwitch() {
        UserModel alice = user(ALICE, null);
        for (boolean idToken : new boolean[]{true, false}) {
            for (String userinfo : new String[]{"true", "false"}) {
                AccessToken token = new AccessToken();
                token.issuer(ISSUER);
                new LWSSubMapper().transformUserInfoToken(token, mapper(Map.of(
                        OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, String.valueOf(idToken),
                        OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO, userinfo)),
                        session(List.of(alice), null), userSession(alice), null);
                assertEquals(idToken ? HOSTED : null, token.getOtherClaims().get("sub"),
                        "ID Token " + idToken + ", userinfo " + userinfo);
            }
        }
    }

    private static UserProfileProvider profile(UPConfig config) {
        return (UserProfileProvider) Proxy.newProxyInstance(LWSSubMapperTest.class.getClassLoader(),
                new Class<?>[]{UserProfileProvider.class}, (proxy, method, args) -> {
                    if ("getConfiguration".equals(method.getName())) {
                        return config;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    @Test
    void knowsWhenTheUserCanEditTheirOwnWebId() {
        UPConfig unmanaged = new UPConfig();
        unmanaged.setUnmanagedAttributePolicy(UPConfig.UnmanagedAttributePolicy.ENABLED);
        assertTrue(LWSSubMapper.userEditable(profile(unmanaged), "lws_webid"));
        unmanaged.setUnmanagedAttributePolicy(UPConfig.UnmanagedAttributePolicy.ADMIN_EDIT);
        assertFalse(LWSSubMapper.userEditable(profile(unmanaged), "lws_webid"));
        unmanaged.setUnmanagedAttributePolicy(null);
        assertFalse(LWSSubMapper.userEditable(profile(unmanaged), "lws_webid"));

        UPConfig declared = new UPConfig();
        declared.setUnmanagedAttributePolicy(UPConfig.UnmanagedAttributePolicy.ENABLED);
        declared.addOrReplaceAttribute(new UPAttribute("lws_webid",
                new UPAttributePermissions(Set.of("admin", "user"), Set.of("admin"))));
        assertFalse(LWSSubMapper.userEditable(profile(declared), "lws_webid"), "declared: its own permissions decide");
        declared.addOrReplaceAttribute(new UPAttribute("lws_webid",
                new UPAttributePermissions(Set.of("admin", "user"), Set.of("admin", "user"))));
        assertTrue(LWSSubMapper.userEditable(profile(declared), "lws_webid"));

        assertFalse(LWSSubMapper.userEditable(null, "lws_webid"));
    }

    /** The warning reads the profile; a profile that says "user-editable" does not change the subject. */
    @Test
    void aUserEditableAttributeIsWarnedAboutNotRefused() {
        UPConfig enabled = new UPConfig();
        enabled.setUnmanagedAttributePolicy(UPConfig.UnmanagedAttributePolicy.ENABLED);
        UserModel alice = user(ALICE, "https://alice.example/profile#me");
        IDToken token = new IDToken();
        token.issuer(ISSUER);
        new LWSSubMapper().transformIDToken(token, mapper(Map.of()), session(List.of(alice), profile(enabled)),
                userSession(alice), null);
        assertEquals("https://alice.example/profile#me", token.getSubject());
    }
}
