/*
 * Copyright Erich Bremer.
 *
 * Factory for the LWS realm resource provider. Mounting id "lws" exposes the endpoints under
 * {issuer}/lws (i.e. {frontendUrl}/realms/{realm}/lws).
 */
package com.ebremer.lws.authn.openid.resource;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import com.ebremer.lws.authn.openid.LWSConstants;

/**
 * @author Erich Bremer
 */
public class LWSResourceProviderFactory implements RealmResourceProviderFactory {

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new LWSResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        // no configuration
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // nothing to do
    }

    @Override
    public void close() {
        // nothing to do
    }

    @Override
    public String getId() {
        return LWSConstants.RESOURCE_PROVIDER_ID;
    }
}
