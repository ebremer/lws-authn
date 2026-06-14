/*
 * Copyright Erich Bremer.
 *
 * Factory for the self-signed CID realm resource provider. Mounting id "lws-ssi-cid" exposes the
 * endpoints under {frontendUrl}/realms/{realm}/lws-ssi-cid.
 */
package com.ebremer.lws.authn.ssicid.resource;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import com.ebremer.lws.authn.ssicid.SsiCidConstants;

/**
 * @author Erich Bremer
 */
public class SsiCidResourceProviderFactory implements RealmResourceProviderFactory {

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new SsiCidResourceProvider(session);
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
        return SsiCidConstants.RESOURCE_PROVIDER_ID;
    }
}
