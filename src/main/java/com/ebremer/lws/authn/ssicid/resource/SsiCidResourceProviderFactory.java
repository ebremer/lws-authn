/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
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
import com.ebremer.lws.authn.config.EndpointSettings;

/**
 * @author Erich Bremer
 */
public class SsiCidResourceProviderFactory implements RealmResourceProviderFactory {

    /**
     * This provider's settings. Held on the factory because {@link Config.Scope} is only offered here,
     * and read eagerly so a misconfiguration is logged at startup rather than once per request.
     */
    private volatile EndpointSettings settings = EndpointSettings.defaults(SsiCidConstants.RESOURCE_PROVIDER_ID);

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new SsiCidResourceProvider(session, settings);
    }

    @Override
    public void init(Config.Scope config) {
        this.settings = EndpointSettings.from(SsiCidConstants.RESOURCE_PROVIDER_ID, config);
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
