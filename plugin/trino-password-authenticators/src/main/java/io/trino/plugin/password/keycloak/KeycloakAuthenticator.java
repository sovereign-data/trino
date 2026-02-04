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

import com.google.inject.Inject;
import io.airlift.log.Logger;
import io.trino.plugin.password.Credential;
import io.trino.spi.security.AccessDeniedException;
import io.trino.spi.security.PasswordAuthenticator;

import java.security.Principal;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.requireNonNull;

/**
 * Keycloak password authenticator with automatic token refresh.
 *
 * This authenticator:
 * 1. Authenticates users against Keycloak using password grant
 * 2. Caches tokens with their expiry time
 * 3. Automatically refreshes tokens before they expire
 * 4. Propagates the access token as an extra credential for downstream catalogs
 */
public class KeycloakAuthenticator
        implements PasswordAuthenticator
{
    private static final Logger log = Logger.get(KeycloakAuthenticator.class);

    // Refresh tokens 60 seconds before expiry to avoid race conditions
    private static final int REFRESH_BUFFER_SECONDS = 60;

    private final KeycloakAuthenticatorClient client;
    private final String tokenCredentialName;
    private final long cacheTtlMillis;

    // Cache of user credentials to their token info
    private final ConcurrentHashMap<Credential, CachedToken> tokenCache = new ConcurrentHashMap<>();

    @Inject
    public KeycloakAuthenticator(KeycloakAuthenticatorClient client, KeycloakAuthenticatorConfig config)
    {
        this.client = requireNonNull(client, "client is null");
        requireNonNull(config, "config is null");
        this.tokenCredentialName = config.getTokenCredentialName();
        this.cacheTtlMillis = config.getTokenCacheTtl().toMillis();

        log.info("Keycloak authenticator initialized with token refresh support, credential name: %s", tokenCredentialName);
    }

    @Override
    public Principal createAuthenticatedPrincipal(String user, String password)
    {
        Credential credential = new Credential(user, password);

        CachedToken cachedToken = tokenCache.get(credential);

        if (cachedToken != null) {
            // Check if we need to refresh
            if (cachedToken.needsRefresh()) {
                log.debug("Token for user '%s' needs refresh (expires at %s)", user, cachedToken.expiresAt);
                cachedToken = refreshOrReauthenticate(credential, cachedToken);
            } else if (cachedToken.isExpired()) {
                log.debug("Token for user '%s' is expired, re-authenticating", user);
                cachedToken = authenticate(credential);
            } else {
                log.debug("Using cached token for user '%s' (expires at %s)", user, cachedToken.expiresAt);
            }
        } else {
            log.debug("No cached token for user '%s', authenticating", user);
            cachedToken = authenticate(credential);
        }

        // Return principal with fresh token
        Map<String, String> extraCredentials = Map.of(
                tokenCredentialName, cachedToken.accessToken);
        return new KeycloakPrincipal(user, extraCredentials);
    }

    private CachedToken authenticate(Credential credential)
    {
        String user = credential.getUser();
        String password = credential.getPassword();

        log.debug("Authenticating user '%s' via Keycloak", user);

        try {
            KeycloakAuthenticatorClient.TokenResponse tokenResponse = client.authenticate(user, password);

            CachedToken cachedToken = new CachedToken(
                    tokenResponse.getAccessToken(),
                    tokenResponse.getRefreshToken(),
                    tokenResponse.getExpiresIn(),
                    password);

            tokenCache.put(credential, cachedToken);

            log.info("Successfully authenticated user '%s' via Keycloak (token expires at %s)",
                    user, cachedToken.expiresAt);

            return cachedToken;
        }
        catch (KeycloakAuthenticatorClient.KeycloakAuthenticationException e) {
            log.debug("Authentication failed for user '%s': %s", user, e.getMessage());
            tokenCache.remove(credential);
            throw new AccessDeniedException("Invalid username or password");
        }
        catch (Exception e) {
            log.error(e, "Keycloak authentication error for user '%s'", user);
            tokenCache.remove(credential);
            throw new RuntimeException("Authentication failed", e);
        }
    }

    private CachedToken refreshOrReauthenticate(Credential credential, CachedToken cachedToken)
    {
        String user = credential.getUser();

        // Try refresh token first
        if (cachedToken.refreshToken != null) {
            try {
                log.debug("Attempting token refresh for user '%s'", user);
                KeycloakAuthenticatorClient.TokenResponse tokenResponse =
                        client.refreshToken(cachedToken.refreshToken);

                CachedToken newToken = new CachedToken(
                        tokenResponse.getAccessToken(),
                        tokenResponse.getRefreshToken(),
                        tokenResponse.getExpiresIn(),
                        cachedToken.password);

                tokenCache.put(credential, newToken);

                log.info("Successfully refreshed token for user '%s' (new expiry: %s)",
                        user, newToken.expiresAt);

                return newToken;
            }
            catch (Exception e) {
                log.debug("Token refresh failed for user '%s', falling back to re-authentication: %s",
                        user, e.getMessage());
            }
        }

        // Refresh failed or no refresh token, re-authenticate with stored password
        return authenticate(credential);
    }

    /**
     * Cached token with expiry tracking and refresh support.
     */
    private static class CachedToken
    {
        final String accessToken;
        final String refreshToken;
        final Instant expiresAt;
        final String password; // Stored for re-authentication fallback

        CachedToken(String accessToken, String refreshToken, int expiresInSeconds, String password)
        {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            // Calculate absolute expiry time
            this.expiresAt = Instant.now().plusSeconds(expiresInSeconds);
            this.password = password;
        }

        boolean isExpired()
        {
            return Instant.now().isAfter(expiresAt);
        }

        boolean needsRefresh()
        {
            // Refresh if token expires within REFRESH_BUFFER_SECONDS
            return Instant.now().isAfter(expiresAt.minusSeconds(REFRESH_BUFFER_SECONDS));
        }
    }
}
