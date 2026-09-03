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
import com.ebremer.lws.authn.verify.VerifyAccess;

/**
 * @author Erich Bremer
 */
public class LWSResourceProviderFactory implements RealmResourceProviderFactory {

    /**
     * Access policy for the verify endpoint. Held on the factory because {@link Config.Scope} is only
     * offered here, and read eagerly so a misconfiguration is logged at startup rather than per request.
     */
    private volatile VerifyAccess verifyAccess = VerifyAccess.defaults();

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new LWSResourceProvider(session, verifyAccess);
    }

    @Override
    public void init(Config.Scope config) {
        this.verifyAccess = VerifyAccess.from(config);
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
