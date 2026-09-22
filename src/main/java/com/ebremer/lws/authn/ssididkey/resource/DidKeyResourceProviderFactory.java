/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Factory for the did:key realm resource provider. Mounting id "lws-ssi-did-key" exposes the endpoint
 * under {frontendUrl}/realms/{realm}/lws-ssi-did-key.
 */
package com.ebremer.lws.authn.ssididkey.resource;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import com.ebremer.lws.authn.ssididkey.DidKeyConstants;
import com.ebremer.lws.authn.config.EndpointSettings;

/**
 * @author Erich Bremer
 */
public class DidKeyResourceProviderFactory implements RealmResourceProviderFactory {

    private static final Logger log = Logger.getLogger(DidKeyResourceProviderFactory.class);

    /**
     * This provider's settings. Held on the factory because {@link Config.Scope} is only offered here,
     * and read eagerly so a misconfiguration is logged at startup rather than once per request.
     */
    private volatile EndpointSettings settings = EndpointSettings.defaults(DidKeyConstants.RESOURCE_PROVIDER_ID);

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new DidKeyResourceProvider(session, settings);
    }

    @Override
    public void init(Config.Scope config) {
        this.settings = EndpointSettings.from(DidKeyConstants.RESOURCE_PROVIDER_ID, config);
        log.warnf("The LWS self-signed did:key authentication suite was discontinued on 2026-09-18 in favour of the "
                + "self-signed CID suite, which verifies did:key subjects itself. The '%s' endpoint still answers, "
                + "and marks every response deprecated; point callers at 'lws-ssi-cid' instead, then turn this one "
                + "off with --spi-realm-restapi-extension--%s--enabled=false.",
                DidKeyConstants.RESOURCE_PROVIDER_ID, DidKeyConstants.RESOURCE_PROVIDER_ID);
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
        return DidKeyConstants.RESOURCE_PROVIDER_ID;
    }
}
