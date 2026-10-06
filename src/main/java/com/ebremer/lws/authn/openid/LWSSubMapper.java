/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * LWS WebID subject mapper.
 *
 * The LWS 1.0 OpenID Connect Authentication Suite uses an OpenID Connect ID Token as an LWS
 * authentication credential. Unlike a plain Keycloak token (whose {@code sub} is an opaque user id),
 * an LWS credential's {@code sub} MUST be a dereferenceable controlled identifier (a "WebID"): a
 * verifier dereferences it to a controlled identifier document and confirms it lists this issuer as
 * an {@code https://www.w3.org/ns/lws#OpenIdProvider} service.
 *
 * This protocol mapper sets {@code sub} to that WebID. By default it derives a Keycloak-hosted
 * controlled identifier document URL ({@code {issuer}/lws/cid/{userId}}, served by
 * {@code LWSResourceProvider}); alternatively it can read a WebID the user already owns from a
 * configurable user attribute.
 */
package com.ebremer.lws.authn.openid;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.userprofile.config.UPAttribute;
import org.keycloak.representations.userprofile.config.UPConfig;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;
import org.keycloak.userprofile.UserProfileProvider;

import com.ebremer.lws.authn.http.CidEndpoint;

/**
 * Sets the {@code sub} claim to the user's LWS WebID so Keycloak ID Tokens can serve as LWS
 * authentication credentials.
 *
 * @author Erich Bremer
 */
public class LWSSubMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final org.jboss.logging.Logger log = org.jboss.logging.Logger.getLogger(LWSSubMapper.class);

    public static final String PROVIDER_ID = "lws-webid-sub-mapper";

    /** Config key: name of the user attribute holding an externally-hosted WebID. */
    public static final String WEBID_ATTRIBUTE = "lws.webid.attribute";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty attr = new ProviderConfigProperty();
        attr.setName(WEBID_ATTRIBUTE);
        attr.setLabel("WebID user attribute");
        attr.setType(ProviderConfigProperty.STRING_TYPE);
        attr.setHelpText("Optional. Name of the user attribute holding the user's WebID / controlled "
                + "identifier (used as the 'sub' claim). When empty, or unset for a given user, a "
                + "Keycloak-hosted controlled identifier document URL is derived automatically: "
                + "{issuer}/lws/cid/{userId}. SECURITY: this attribute becomes the credential's subject, "
                + "so it MUST NOT be user-writable — a user who can set it can claim any WebID. If it is "
                + "an unmanaged attribute, set the realm's unmanaged attribute policy to ADMIN_EDIT (not "
                + "ENABLED); if it is declared in the user profile, give it admin-only write permission. "
                + "A value that is not an absolute http(s) URL of at most 255 ASCII characters, that names "
                + "another URL of this realm's, or that another user of the realm also holds, is ignored — "
                + "with a warning in the server log — and the Keycloak-hosted WebID used instead.");
        CONFIG_PROPERTIES.add(attr);

        CONFIG_PROPERTIES.add(includeProperty(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN,
                "Add to ID token and userinfo", "Set the LWS WebID as the 'sub' claim of the ID token (the LWS "
                        + "credential) and of the userinfo response. The two go together: OpenID Connect Core "
                        + "§5.3.2 requires userinfo's 'sub' to match the ID token's exactly.",
                true));
        CONFIG_PROPERTIES.add(includeProperty(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN,
                "Add to access token", "Off by default. Set the LWS WebID as the 'sub' claim of the access token. "
                        + "An access token is not an LWS credential; with a WebID 'sub' it looks like one to a "
                        + "verifier that does not check the token's type, so a party the user handed an access "
                        + "token to could present it as the user's credential. Turn on only if something "
                        + "downstream needs the WebID in the access token.",
                false));
    }

    private static ProviderConfigProperty includeProperty(String name, String label, String help, boolean onByDefault) {
        return new ProviderConfigProperty(name, label, help, ProviderConfigProperty.BOOLEAN_TYPE,
                String.valueOf(onByDefault));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "LWS WebID Subject";
    }

    @Override
    public String getHelpText() {
        return "Sets the 'sub' claim to the user's LWS WebID (a dereferenceable controlled identifier) so "
                + "ID Tokens can be used as LWS authentication credentials per the LWS 1.0 OpenID Connect "
                + "Authentication Suite.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        if (include(mappingModel, OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, false)) {
            token.setSubject(resolveWebId(token, mappingModel, session, userSession));
        }
        return token;
    }

    @Override
    public IDToken transformIDToken(IDToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        if (include(mappingModel, OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, true)) {
            token.setSubject(resolveWebId(token, mappingModel, session, userSession));
        }
        return token;
    }

    /**
     * Userinfo's {@code sub} follows the ID Token's (R-30): OIDC Core §5.3.2, "The sub Claim in the
     * UserInfo Response MUST be verified to exactly match the sub Claim in the ID Token". A separate
     * "Add to userinfo" switch could only make them differ, so there is none; one a mapper was saved
     * with is ignored.
     */
    @Override
    public AccessToken transformUserInfoToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        if (include(mappingModel, OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, true)) {
            // userinfo subject is conveyed as an "other" claim, matching Keycloak's pairwise mapper
            token.getOtherClaims().put("sub", resolveWebId(token, mappingModel, session, userSession));
        }
        return token;
    }

    /** Longest {@code sub} OIDC Core §2 allows: "It MUST NOT exceed 255 ASCII characters in length." */
    static final int MAX_SUBJECT_LENGTH = 255;

    /** How often a realm's user profile is re-read to see whether the WebID attribute is user-editable. */
    private static final long PROFILE_CHECK_INTERVAL_MS = 10 * 60 * 1000L;

    private static final Map<String, Long> PROFILE_CHECKED = new ConcurrentHashMap<>();
    private static final Set<String> LONG_SUBJECT_WARNED = ConcurrentHashMap.newKeySet();

    /**
     * Returns the WebID to use as {@code sub}: the configured user attribute when present and
     * acceptable, otherwise the Keycloak-hosted controlled identifier document URL for the user.
     */
    private String resolveWebId(IDToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession) {
        UserModel user = userSession.getUser();
        RealmModel realm = userSession.getRealm();
        String issuer = issuer(token, session, realm);
        String hosted = CidEndpoint.documentUrl(issuer, LWSConstants.RESOURCE_PROVIDER_ID, LWSConstants.CID_PATH,
                user.getId());
        String attribute = mappingModel.getConfig().get(WEBID_ATTRIBUTE);
        if (attribute != null && !attribute.isBlank()) {
            String value = user.getFirstAttribute(attribute);
            if (value != null && !value.isBlank()) {
                // Trimmed, because this value is about to become a claim that every verifier
                // treats as a URI. Surrounding whitespace is invisible in the Keycloak admin
                // console and survives a copy-paste, and returning it verbatim emitted a `sub`
                // of " https://example.org/id/agent" — which is not an absolute URL, so a
                // conforming verifier cannot dereference it and MUST refuse the credential.
                // The failure is silent and total: the OP issues a token that looks right, and
                // every LWS server rejects it as invalid_token with nothing to point at.
                // A blank-after-trim value is treated as no value at all, exactly as an unset
                // attribute already is, and falls through to the Keycloak-hosted WebID.
                String webId = value.trim();
                warnIfUserEditable(session, realm, attribute);
                // A value that cannot be used falls back to the hosted WebID, which at least works,
                // and the log says why: emitting it would give a token that looks right and is refused
                // everywhere — or, for the cases below, one that speaks for somebody else.
                String problem = problem(webId, issuer, hosted);
                if (problem == null) {
                    problem = sharedWithAnotherUser(session, realm, user, attribute, value, webId);
                }
                if (problem == null) {
                    return webId;
                }
                log.warnf("User %s has a '%s' attribute that %s; falling back to the Keycloak-hosted WebID",
                        user.getId(), attribute, problem);
            }
        }
        if (hosted.length() > MAX_SUBJECT_LENGTH && LONG_SUBJECT_WARNED.add(realm.getId())) {
            log.warnf("Realm %s issues hosted WebIDs longer than the %d characters OpenID Connect allows a 'sub' "
                    + "(for user %s); shorten the issuer URL or the user-storage ids",
                    realm.getName(), MAX_SUBJECT_LENGTH, user.getId());
        }
        return hosted;
    }

    /**
     * Why {@code webId} cannot be a credential's subject for this user, or {@code null} if it can (R-30).
     *
     * <ul>
     *   <li>It must be an absolute {@code http}/{@code https} URL: the subject of an LWS credential MUST
     *       be a URI (core §4.1), and the OpenID suite has a verifier dereference it.</li>
     *   <li>At most 255 ASCII characters (OIDC Core §2).</li>
     *   <li>Nothing in this realm's own URL space but the user's own hosted WebID. {@code {issuer}/lws/cid/
     *       <another user's id>} is a document this realm serves listing this issuer as the subject's
     *       OpenID provider, so a token naming it would verify — as that other user. That was prevented
     *       only by the deployment policy keeping the attribute admin-only.</li>
     * </ul>
     *
     * @param issuer this realm's issuer URL
     * @param hosted the user's own hosted WebID
     */
    static String problem(String webId, String issuer, String hosted) {
        URI uri;
        try {
            uri = new URI(webId);
        } catch (URISyntaxException notAUri) {
            return "is not an absolute http(s) URL";
        }
        String scheme = uri.getScheme();
        if (!uri.isAbsolute() || uri.getHost() == null || uri.getHost().isBlank()
                || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            return "is not an absolute http(s) URL";
        }
        if (webId.length() > MAX_SUBJECT_LENGTH || !webId.chars().allMatch(c -> c > 0x20 && c < 0x7f)) {
            return "is not at most " + MAX_SUBJECT_LENGTH + " ASCII characters, as OpenID Connect requires of 'sub'";
        }
        if (!webId.equals(hosted) && withinRealm(uri.normalize(), issuer)) {
            return "names a URL in this realm's own namespace other than the user's own WebID";
        }
        return null;
    }

    /** True iff {@code uri} is {@code issuer} or under it; host and path compared without regard to case. */
    private static boolean withinRealm(URI uri, String issuer) {
        URI realm;
        try {
            realm = new URI(issuer);
        } catch (URISyntaxException unreadable) {
            return false;
        }
        if (realm.getHost() == null || !realm.getScheme().equalsIgnoreCase(uri.getScheme())
                || !realm.getHost().equalsIgnoreCase(uri.getHost()) || port(realm) != port(uri)) {
            return false;
        }
        String realmPath = realm.getPath() == null ? "" : realm.getPath().toLowerCase(Locale.ROOT);
        String path = uri.getPath() == null ? "" : uri.getPath().toLowerCase(Locale.ROOT);
        String base = realmPath.endsWith("/") ? realmPath.substring(0, realmPath.length() - 1) : realmPath;
        return path.equals(base) || path.equals(base + "/") || path.startsWith(base + "/");
    }

    private static int port(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    /**
     * Why the WebID cannot be this user's because another user of the realm holds it too, or
     * {@code null}. OIDC Core §2: a {@code sub} is "a locally unique and never reassigned identifier";
     * two users given one WebID would be one subject to every verifier, each able to act as the other.
     * Neither gets it until an administrator decides whose it is.
     */
    private static String sharedWithAnotherUser(KeycloakSession session, RealmModel realm, UserModel user,
            String attribute, String value, String webId) {
        for (String candidate : value.equals(webId) ? List.of(value) : List.of(value, webId)) {
            boolean shared = session.users().searchForUserByUserAttributeStream(realm, attribute, candidate)
                    .anyMatch(other -> !user.getId().equals(other.getId()));
            if (shared) {
                return "another user of the realm also holds";
            }
        }
        return null;
    }

    /**
     * Warns, at most every ten minutes per realm and attribute, when the realm's user profile lets the
     * user write the WebID attribute (R-30): a user who can write it chooses the subject of their own
     * credentials. Declared in the profile, that is an {@code edit} permission for {@code user};
     * undeclared, it is the unmanaged attribute policy {@code ENABLED}.
     */
    private static void warnIfUserEditable(KeycloakSession session, RealmModel realm, String attribute) {
        String key = realm.getId() + " " + attribute;
        long now = System.currentTimeMillis();
        Long last = PROFILE_CHECKED.get(key);
        if (last != null && now - last < PROFILE_CHECK_INTERVAL_MS) {
            return;
        }
        PROFILE_CHECKED.put(key, now);
        try {
            if (userEditable(session.getProvider(UserProfileProvider.class), attribute)) {
                log.warnf("Realm %s lets users edit their own '%s' attribute, which the LWS WebID mapper makes "
                        + "the subject of their credentials: any user can claim a WebID that trusts this issuer. "
                        + "Make it admin-only (unmanaged attribute policy ADMIN_EDIT, or no 'user' edit "
                        + "permission in the user profile)", realm.getName(), attribute);
            }
        } catch (RuntimeException unreadable) {
            log.debugf(unreadable, "Could not read realm %s's user profile", realm.getName());
        }
    }

    /** True iff {@code profile} lets a user edit their own {@code attribute}. */
    static boolean userEditable(UserProfileProvider profile, String attribute) {
        UPConfig config = profile == null ? null : profile.getConfiguration();
        if (config == null) {
            return false;
        }
        UPAttribute declared = config.getAttributes() == null ? null : config.getAttribute(attribute);
        if (declared != null) {
            // "user" is the role the user profile gives the user themselves (UPConfigUtils.ROLE_USER).
            return declared.getPermissions() != null && declared.getPermissions().getEdit() != null
                    && declared.getPermissions().getEdit().contains("user");
        }
        return config.getUnmanagedAttributePolicy() == UPConfig.UnmanagedAttributePolicy.ENABLED;
    }

    /** The token's issuer, or this realm's issuer URL when the token does not carry one yet. */
    private static String issuer(IDToken token, KeycloakSession session, RealmModel realm) {
        String issuer = token.getIssuer();
        if (issuer == null || issuer.isBlank()) {
            issuer = Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
        }
        return issuer;
    }

    /** The mapper's setting for {@code key}, or {@code onByDefault} when it was never set (R-05). */
    private static boolean include(ProtocolMapperModel mappingModel, String key, boolean onByDefault) {
        String value = mappingModel.getConfig().get(key);
        return value == null || value.isBlank() ? onByDefault : Boolean.parseBoolean(value);
    }
}
