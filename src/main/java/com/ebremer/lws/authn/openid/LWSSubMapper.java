/*
 * Copyright Erich Bremer.
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

import java.util.ArrayList;
import java.util.List;

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
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;

/**
 * Sets the {@code sub} claim to the user's LWS WebID so Keycloak ID Tokens can serve as LWS
 * authentication credentials.
 *
 * @author Erich Bremer
 */
public class LWSSubMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

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
                + "ENABLED); if it is declared in the user profile, give it admin-only write permission.");
        CONFIG_PROPERTIES.add(attr);

        CONFIG_PROPERTIES.add(includeProperty(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN,
                "Add to ID token", "Set the LWS WebID as the 'sub' claim of the ID token (the LWS credential)."));
        CONFIG_PROPERTIES.add(includeProperty(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN,
                "Add to access token", "Set the LWS WebID as the 'sub' claim of the access token."));
        CONFIG_PROPERTIES.add(includeProperty(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO,
                "Add to userinfo", "Set the LWS WebID as the 'sub' claim returned from the userinfo endpoint."));
    }

    private static ProviderConfigProperty includeProperty(String name, String label, String help) {
        return new ProviderConfigProperty(name, label, help, ProviderConfigProperty.BOOLEAN_TYPE, "true");
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
        if (include(mappingModel, OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN)) {
            token.setSubject(resolveWebId(token, mappingModel, session, userSession));
        }
        return token;
    }

    @Override
    public IDToken transformIDToken(IDToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        if (include(mappingModel, OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN)) {
            token.setSubject(resolveWebId(token, mappingModel, session, userSession));
        }
        return token;
    }

    @Override
    public AccessToken transformUserInfoToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        if (include(mappingModel, OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO)) {
            // userinfo subject is conveyed as an "other" claim, matching Keycloak's pairwise mapper
            token.getOtherClaims().put("sub", resolveWebId(token, mappingModel, session, userSession));
        }
        return token;
    }

    /**
     * Returns the WebID to use as {@code sub}: the configured user attribute when present,
     * otherwise the Keycloak-hosted controlled identifier document URL for the user.
     */
    private String resolveWebId(IDToken token, ProtocolMapperModel mappingModel, KeycloakSession session,
            UserSessionModel userSession) {
        UserModel user = userSession.getUser();
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
                if (!webId.isEmpty()) {
                    return webId;
                }
            }
        }
        return hostedWebId(token, session, userSession.getRealm(), user);
    }

    /** Derives {@code {issuer}/lws/cid/{userId}} — the document served by {@code LWSResourceProvider}. */
    private String hostedWebId(IDToken token, KeycloakSession session, RealmModel realm, UserModel user) {
        String issuer = token.getIssuer();
        if (issuer == null || issuer.isBlank()) {
            issuer = Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
        }
        return issuer + "/" + LWSConstants.RESOURCE_PROVIDER_ID + "/" + LWSConstants.CID_PATH + "/" + user.getId();
    }

    /** Reads an include flag, defaulting to {@code true} when unset (LWS wants the WebID in all tokens). */
    private static boolean include(ProtocolMapperModel mappingModel, String key) {
        String value = mappingModel.getConfig().get(key);
        return value == null || value.isBlank() || Boolean.parseBoolean(value);
    }
}
