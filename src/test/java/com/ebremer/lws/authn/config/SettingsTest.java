/*
 * Copyright Erich Bremer.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.ebremer.lws.authn.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.models.RealmModel;

import com.ebremer.lws.authn.jose.JwsChecks;
import com.ebremer.lws.authn.net.OutboundHttp;
import com.ebremer.lws.authn.net.SsrfGuard;
import com.ebremer.lws.authn.verify.VerifyAccess;

/**
 * P3-6. {@code init(Config.Scope)} used to be empty in all four factories and the SSRF allow-list was
 * readable only from a system property or environment variable, so there was no supported way to set
 * timeouts, clock skew, audiences or cache lifetimes, or to turn an endpoint off.
 */
class SettingsTest {

    /**
     * A {@link Config.Scope} backed by a map. A proxy rather than an implementation: this code only
     * ever calls {@code get(String)}, and the interface has a dozen other methods that would be dead
     * weight — and would have to be chased every time Keycloak adds one.
     */
    private static Config.Scope scope(String... keysAndValues) {
        Map<String, String> values = new HashMap<>();
        for (int i = 0; i < keysAndValues.length; i += 2) {
            values.put(keysAndValues[i], keysAndValues[i + 1]);
        }
        return (Config.Scope) Proxy.newProxyInstance(
                SettingsTest.class.getClassLoader(), new Class<?>[]{Config.Scope.class},
                (proxy, method, args) -> {
                    if ("get".equals(method.getName()) && args != null && args.length == 1) {
                        return values.get((String) args[0]);
                    }
                    if ("toString".equals(method.getName())) {
                        return "scope" + values;
                    }
                    throw new UnsupportedOperationException("unexpected Config.Scope." + method.getName());
                });
    }

    /** A {@link RealmModel} carrying exactly one attribute; nothing else may be called on it. */
    private static RealmModel realmWith(String key, String value) {
        return (RealmModel) Proxy.newProxyInstance(
                SettingsTest.class.getClassLoader(), new Class<?>[]{RealmModel.class},
                (proxy, method, args) -> {
                    if ("getAttribute".equals(method.getName()) && args != null && args.length == 1) {
                        return key.equals(args[0]) ? value : null;
                    }
                    if ("toString".equals(method.getName())) {
                        return "realm[" + key + "=" + value + "]";
                    }
                    throw new UnsupportedOperationException("this test only reads realm attributes");
                });
    }

    @AfterEach
    void restoreDefaults() {
        ServerSettings.reset();
        System.clearProperty("lws.authn.clockSkewSeconds");
        System.clearProperty("lws.authn.allowedInternalHosts");
        System.clearProperty("lws.authn.http.timeoutMillis");
    }

    // ------------------------------------------------------------------ Settings: the three sources

    @Test
    void theScopeWinsOverThePropertyWhichWinsOverTheDefault() {
        System.setProperty("lws.authn.clockSkewSeconds", "30");
        assertEquals("5", Settings.get(scope("clock-skew-seconds", "5"),
                "clock-skew-seconds", "lws.authn.clockSkewSeconds", "NO_SUCH_ENV", "60"));
        assertEquals("30", Settings.get(null,
                "clock-skew-seconds", "lws.authn.clockSkewSeconds", "NO_SUCH_ENV", "60"));

        System.clearProperty("lws.authn.clockSkewSeconds");
        assertEquals("60", Settings.get(null,
                "clock-skew-seconds", "lws.authn.clockSkewSeconds", "NO_SUCH_ENV", "60"));
    }

    @Test
    void isSetTellsNotConfiguredApartFromConfiguredToTheDefault() {
        assertFalse(Settings.isSet(scope(), "enabled", "no.such.property", "NO_SUCH_ENV"));
        assertTrue(Settings.isSet(scope("enabled", "true"), "enabled", "no.such.property", "NO_SUCH_ENV"));
    }

    @Test
    void malformedNumbersAndBooleansFallBackRatherThanThrow() {
        assertEquals(7L, Settings.getLong(scope("k", "not a number"), "k", "no.such", "NO_SUCH", 7L, 0, 100));
        assertTrue(Settings.getBoolean(scope("k", "yes please"), "k", "no.such", "NO_SUCH", true));
        assertFalse(Settings.getBoolean(scope("k", "FALSE"), "k", "no.such", "NO_SUCH", true));
    }

    /**
     * R-35. A number out of range is clamped — {@code http-timeout-millis=99999999999} used to overflow
     * an {@code int} and quietly become the default — and a negative one is a mistake, not "off".
     */
    @Test
    void outOfRangeIsClampedAndNegativeIsInvalid() {
        assertEquals(100, Settings.getInt(scope("k", "99999999999999"), "k", "no.such", "NO_SUCH", 7, 0, 100));
        assertEquals(5L, Settings.getLong(scope("k", "1"), "k", "no.such", "NO_SUCH", 7L, 5, 100));
        assertEquals(7L, Settings.getLong(scope("k", "-1"), "k", "no.such", "NO_SUCH", 7L, 0, 100));

        ServerSettings.contribute("lws", scope("http-timeout-millis", "99999999999"));
        assertEquals(60_000, OutboundHttp.timeoutMillis());

        EndpointSettings negative = EndpointSettings.from("lws", scope("rate-limit", "-1", "cid-rate-limit", "-1"));
        assertNotNull(negative.getCidLimiter(), "rate-limit=-1 used to turn limiting off");
        assertEquals(EndpointSettings.DEFAULT_CID_RATE_LIMIT, negative.getCidLimiter().getPermitsPerMinute());
        assertTrue(negative.describe().contains("rate-limit=" + VerifyAccess.DEFAULT_RATE_LIMIT + "/min"),
                negative.describe());
    }

    /**
     * R-35. Any provider's scope comes before the system property, whichever order the providers are
     * initialised in. The second provider, with nothing in its scope, used to read the property as its
     * own say-so and overwrite the first one's scope value.
     */
    @Test
    void aScopeValueBeatsThePropertyWhateverOrderTheProvidersStartIn() {
        System.setProperty("lws.authn.http.timeoutMillis", "60000");
        ServerSettings.contribute("lws", scope("http-timeout-millis", "1000"));
        ServerSettings.contribute("lws-saml", scope());
        assertEquals(1000, OutboundHttp.timeoutMillis());

        ServerSettings.reset();
        ServerSettings.contribute("lws-saml", scope());
        assertEquals(60_000, OutboundHttp.timeoutMillis(), "with no scope naming it, the property applies");
        ServerSettings.contribute("lws", scope("http-timeout-millis", "1000"));
        assertEquals(1000, OutboundHttp.timeoutMillis());
    }

    /** R-35. The allow-list matches however a host is spelt: bracketed, with a trailing dot, any case. */
    @Test
    void allowListEntriesAreReadInTheirUsualSpellings() {
        ServerSettings.contribute("lws", scope("allowed-internal-hosts", "[::1], KC.Internal. ,0:0:0:0:0:0:0:2"));
        Set<String> allowed = SsrfGuard.configuredAllowlist();
        for (String host : new String[]{"[::1]", "::1", "0:0:0:0:0:0:0:1", "kc.internal", "kc.internal.",
                "KC.INTERNAL", "[::2]"}) {
            assertTrue(SsrfGuard.secureOrAllowListed("http", host, allowed), host + " in " + allowed);
        }
        assertFalse(SsrfGuard.secureOrAllowListed("http", "kc.internal.example", allowed));
    }

    /** R-35. {@code http-mode} is a setting like the others, read by the same rules, and logged. */
    @Test
    void theHttpModeIsASetting() {
        assertEquals("guarded", ServerSettings.httpMode());
        ServerSettings.contribute("lws", scope("http-mode", "Session"));
        assertEquals("session", ServerSettings.httpMode());
        assertTrue(ServerSettings.describe().contains("http-mode=session"), ServerSettings.describe());
        ServerSettings.reset();
        ServerSettings.contribute("lws", scope("http-mode", "proxy"));
        assertEquals("guarded", ServerSettings.httpMode(), "an unknown mode is the safe one");
    }

    // ----------------------------------------------------------------------------- ServerSettings

    @Test
    void serverWideSettingsReachTheStaticUtilitiesThatUseThem() {
        ServerSettings.contribute("lws", scope(
                "http-timeout-millis", "1500",
                "http-max-response-bytes", "4096",
                "clock-skew-seconds", "5",
                "allowed-internal-hosts", "localhost, Inner.Example "));

        assertEquals(1500, OutboundHttp.timeoutMillis());
        assertEquals(4096L, OutboundHttp.maxResponseBytes());
        assertEquals(5L, JwsChecks.clockSkewSeconds());
        assertEquals(Set.of("localhost", "inner.example"), SsrfGuard.configuredAllowlist(),
                "hosts are trimmed and lower-cased, and reach the guard through the config surface");
    }

    @Test
    void aProviderThatSaysNothingLeavesAServerWideSettingAlone() {
        ServerSettings.contribute("lws", scope("http-timeout-millis", "1500"));
        ServerSettings.contribute("lws-saml", scope("clock-skew-seconds", "5"));

        assertEquals(1500, OutboundHttp.timeoutMillis(), "the SAML provider set nothing about timeouts");
        assertEquals(5L, ServerSettings.clockSkewSeconds());
    }

    @Test
    void absurdValuesAreClampedRatherThanHonoured() {
        ServerSettings.contribute("lws", scope(
                "http-timeout-millis", "1", "clock-skew-seconds", "99999", "http-max-response-bytes", "1"));
        assertEquals(100, OutboundHttp.timeoutMillis());
        assertEquals(600L, ServerSettings.clockSkewSeconds());
        assertEquals(1024L, OutboundHttp.maxResponseBytes());
    }

    @Test
    void theAllowListStillFallsBackToTheSystemProperty() {
        System.setProperty("lws.authn.allowedInternalHosts", "kc.internal");
        assertEquals(Set.of("kc.internal"), SsrfGuard.configuredAllowlist(),
                "an existing deployment configured only by property must keep working");
    }

    @Test
    void resetRestoresTheCompiledInDefaults() {
        ServerSettings.contribute("lws", scope("http-timeout-millis", "1500", "clock-skew-seconds", "5"));
        ServerSettings.reset();
        assertEquals(ServerSettings.DEFAULT_HTTP_TIMEOUT_MILLIS, OutboundHttp.timeoutMillis());
        assertEquals(ServerSettings.DEFAULT_CLOCK_SKEW_SECONDS, JwsChecks.clockSkewSeconds());
        assertTrue(SsrfGuard.configuredAllowlist().isEmpty());
    }

    // --------------------------------------------------------------------------- EndpointSettings

    @Test
    void endpointSettingsDefaultToTheCompiledInValues() {
        EndpointSettings settings = EndpointSettings.from("lws", scope());
        assertTrue(settings.isEnabled(null));
        assertNull(settings.getDefaultAudience());
        assertEquals(EndpointSettings.DEFAULT_CID_CACHE_SECONDS, settings.getCidCacheSeconds());
        assertNotNull(settings.getCidLimiter());
        assertEquals(EndpointSettings.DEFAULT_CID_RATE_LIMIT, settings.getCidLimiter().getPermitsPerMinute());
        assertEquals(VerifyAccess.Mode.BEARER, settings.getVerifyAccess().getMode());
        assertEquals("lws", settings.getProviderId());
    }

    @Test
    void aConfiguredAudienceAppliesWhenTheRequestNamesNone() {
        EndpointSettings settings = EndpointSettings.from("lws", scope("audience", " https://as.example "));
        assertEquals("https://as.example", settings.audienceFor(null));
        assertEquals("https://as.example", settings.audienceFor("  "));
        assertEquals("https://other.example", settings.audienceFor("https://other.example"),
                "an explicit parameter still wins");
    }

    /** R-25: SAML certificates in the request are accepted unless the deployment says otherwise. */
    @Test
    void requestCertificatesCanBeTurnedOff() {
        EndpointSettings byDefault = EndpointSettings.from("lws-saml", scope());
        assertTrue(byDefault.acceptsRequestCertificates());
        assertTrue(byDefault.describe().contains("request-certificates=true"), byDefault.describe());

        EndpointSettings off = EndpointSettings.from("lws-saml", scope("request-certificates", "false"));
        assertFalse(off.acceptsRequestCertificates());
        assertTrue(off.describe().contains("request-certificates=false"), off.describe());

        assertFalse(EndpointSettings.from("lws", scope()).describe().contains("request-certificates"),
                "a SAML setting is not reported for the other suites");
    }

    @Test
    void anEndpointCanBeTurnedOff() {
        assertFalse(EndpointSettings.from("lws-saml", scope("serve", "false")).isEnabled(null));
        assertTrue(EndpointSettings.from("lws-saml", scope("serve", "true")).isEnabled(null));
        // R-35: 'enabled' in a provider's scope is Keycloak's own switch, which never lets the factory
        // load when false; this provider does not read it.
        assertTrue(EndpointSettings.from("lws-saml", scope("enabled", "false")).isEnabled(null));
    }

    @Test
    void aRealmAttributeOverridesTheProviderWideFlagInBothDirections() {
        EndpointSettings on = EndpointSettings.from("lws-saml", scope("serve", "true"));
        EndpointSettings off = EndpointSettings.from("lws-saml", scope("serve", "false"));

        assertFalse(on.isEnabled(realmWith("lws.authn.lws-saml.enabled", "false")));
        assertTrue(off.isEnabled(realmWith("lws.authn.lws-saml.enabled", "true")));
        assertTrue(on.isEnabled(realmWith("lws.authn.lws-saml.enabled", "perhaps")),
                "an attribute that is neither true nor false is ignored, not guessed at");
        assertTrue(on.isEnabled(realmWith("lws.authn.lws.enabled", "false")),
                "the attribute names one provider; another provider's flag must not apply");
    }

    @Test
    void aRateLimitOfZeroTurnsTheCidLimiterOff() {
        assertNull(EndpointSettings.from("lws", scope("cid-rate-limit", "0")).getCidLimiter());
    }

    /**
     * R-12. A runtime option given to {@code kc.sh build} is dropped with no more than a warning in the
     * build's output, so the startup log says what is actually in force — and must not say a secret.
     */
    @Test
    void describesWhatIsInForceWithoutTheSecret() {
        String described = EndpointSettings.from("lws", scope("access", "secret", "secret", "hunter2",
                "audience", "https://as.example", "rate-limit", "30", "cid-rate-limit", "0")).describe();
        assertTrue(described.contains("access=secret"), described);
        assertTrue(described.contains("secret=(set)"), described);
        assertFalse(described.contains("hunter2"), described);
        assertTrue(described.contains("audience=https://as.example"), described);
        assertTrue(described.contains("rate-limit=30/min"), described);
        assertTrue(described.contains("cid-rate-limit=off"), described);

        String bearer = EndpointSettings.from("lws", scope()).describe();
        assertTrue(bearer.contains("access=bearer, role=lws-verifier"), bearer);
        assertTrue(ServerSettings.describe().contains("http-deadline-millis=10000"), ServerSettings.describe());
    }
}
