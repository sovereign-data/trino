/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.plugin.password.keycloak;

import io.airlift.configuration.Config;
import io.airlift.configuration.ConfigDescription;
import io.airlift.configuration.ConfigSecuritySensitive;
import io.airlift.units.Duration;
import io.airlift.units.MinDuration;
import jakarta.validation.constraints.NotNull;

import java.net.URI;

import static java.util.concurrent.TimeUnit.MINUTES;

public class KeycloakAuthenticatorConfig
{
    private URI keycloakUrl;
    private String realm = "master";
    private String clientId;
    private String clientSecret;
    private boolean sslVerification = true;
    private Duration tokenCacheTtl = new Duration(5, MINUTES);
    private String tokenCredentialName = "token";

    @NotNull
    public URI getKeycloakUrl()
    {
        return keycloakUrl;
    }

    @Config("keycloak.url")
    @ConfigDescription("Keycloak server URL (e.g., https://auth.local)")
    public KeycloakAuthenticatorConfig setKeycloakUrl(URI keycloakUrl)
    {
        this.keycloakUrl = keycloakUrl;
        return this;
    }

    @NotNull
    public String getRealm()
    {
        return realm;
    }

    @Config("keycloak.realm")
    @ConfigDescription("Keycloak realm name")
    public KeycloakAuthenticatorConfig setRealm(String realm)
    {
        this.realm = realm;
        return this;
    }

    @NotNull
    public String getClientId()
    {
        return clientId;
    }

    @Config("keycloak.client-id")
    @ConfigDescription("OAuth2 client ID for password grant")
    public KeycloakAuthenticatorConfig setClientId(String clientId)
    {
        this.clientId = clientId;
        return this;
    }

    public String getClientSecret()
    {
        return clientSecret;
    }

    @Config("keycloak.client-secret")
    @ConfigDescription("OAuth2 client secret")
    @ConfigSecuritySensitive
    public KeycloakAuthenticatorConfig setClientSecret(String clientSecret)
    {
        this.clientSecret = clientSecret;
        return this;
    }

    public boolean isSslVerification()
    {
        return sslVerification;
    }

    @Config("keycloak.ssl-verification")
    @ConfigDescription("Enable SSL certificate verification")
    public KeycloakAuthenticatorConfig setSslVerification(boolean sslVerification)
    {
        this.sslVerification = sslVerification;
        return this;
    }

    @NotNull
    @MinDuration("0s")
    public Duration getTokenCacheTtl()
    {
        return tokenCacheTtl;
    }

    @Config("keycloak.token-cache-ttl")
    @ConfigDescription("Duration to cache authentication tokens")
    public KeycloakAuthenticatorConfig setTokenCacheTtl(Duration tokenCacheTtl)
    {
        this.tokenCacheTtl = tokenCacheTtl;
        return this;
    }

    @NotNull
    public String getTokenCredentialName()
    {
        return tokenCredentialName;
    }

    @Config("keycloak.token-credential-name")
    @ConfigDescription("Name of extra credential to store the access token")
    public KeycloakAuthenticatorConfig setTokenCredentialName(String tokenCredentialName)
    {
        this.tokenCredentialName = tokenCredentialName;
        return this;
    }
}
