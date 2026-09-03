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
        assertEquals(7L, Settings.getLong(scope("k", "not a number"), "k", "no.such", "NO_SUCH", 7L));
        assertEquals(7, Settings.getInt(scope("k", "99999999999999"), "k", "no.such", "NO_SUCH", 7));
        assertTrue(Settings.getBoolean(scope("k", "yes please"), "k", "no.such", "NO_SUCH", true));
        assertFalse(Settings.getBoolean(scope("k", "FALSE"), "k", "no.such", "NO_SUCH", true));
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

    @Test
    void anEndpointCanBeTurnedOff() {
        assertFalse(EndpointSettings.from("lws-saml", scope("enabled", "false")).isEnabled(null));
        assertTrue(EndpointSettings.from("lws-saml", scope("enabled", "true")).isEnabled(null));
    }

    @Test
    void aRealmAttributeOverridesTheProviderWideFlagInBothDirections() {
        EndpointSettings on = EndpointSettings.from("lws-saml", scope("enabled", "true"));
        EndpointSettings off = EndpointSettings.from("lws-saml", scope("enabled", "false"));

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
}
