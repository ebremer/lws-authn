/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.openid;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;

/**
 * R-05. The WebID goes into the ID Token — the LWS credential — and not into the access token unless
 * someone asks for it. An access token with a WebID {@code sub} carries everything an LWS verifier that
 * does not check the token's type looks at, so a party the user handed it to could present it as the
 * user's credential.
 */
class LWSSubMapperTest {

    private static String defaultOf(String name) {
        return new LWSSubMapper().getConfigProperties().stream()
                .filter(p -> p.getName().equals(name))
                .map(ProviderConfigProperty::getDefaultValue)
                .map(String::valueOf)
                .findFirst().orElseThrow();
    }

    @Test
    void offersTheWebIdForTheIdTokenAndUserinfoButNotTheAccessToken() {
        assertEquals("true", defaultOf(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN));
        assertEquals("true", defaultOf(OIDCAttributeMapperHelper.INCLUDE_IN_USERINFO));
        assertEquals("false", defaultOf(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN));
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
            token.subject("8f3c1e2a-0000-4000-8000-000000000000");
            // With the access token excluded the mapper never reaches the session, so none is needed.
            new LWSSubMapper().transformAccessToken(token, model, null, null, null);
            assertEquals("8f3c1e2a-0000-4000-8000-000000000000", token.getSubject(), config.toString());
        }
    }
}
