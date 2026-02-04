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
import io.airlift.http.client.HttpClient;
import io.airlift.http.client.HttpStatus;
import io.airlift.http.client.Request;
import io.airlift.http.client.Response;
import io.airlift.http.client.ResponseHandler;
import io.airlift.log.Logger;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static io.airlift.http.client.Request.Builder.preparePost;
import static io.airlift.http.client.StaticBodyGenerator.createStaticBodyGenerator;
import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

public class KeycloakAuthenticatorClient
{
    private static final Logger log = Logger.get(KeycloakAuthenticatorClient.class);

    // Simple regex patterns for JSON parsing (avoids Jackson version conflicts)
    private static final Pattern ACCESS_TOKEN_PATTERN = Pattern.compile("\"access_token\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern TOKEN_TYPE_PATTERN = Pattern.compile("\"token_type\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern EXPIRES_IN_PATTERN = Pattern.compile("\"expires_in\"\\s*:\\s*(\\d+)");
    private static final Pattern REFRESH_TOKEN_PATTERN = Pattern.compile("\"refresh_token\"\\s*:\\s*\"([^\"]+)\"");

    private final HttpClient httpClient;
    private final URI tokenEndpoint;
    private final String clientId;
    private final Optional<String> clientSecret;

    @Inject
    public KeycloakAuthenticatorClient(
            @ForKeycloakAuthenticator HttpClient httpClient,
            KeycloakAuthenticatorConfig config)
    {
        this.httpClient = requireNonNull(httpClient, "httpClient is null");
        requireNonNull(config, "config is null");

        this.tokenEndpoint = URI.create(format("%s/realms/%s/protocol/openid-connect/token",
                config.getKeycloakUrl().toString().replaceAll("/$", ""),
                config.getRealm()));
        this.clientId = config.getClientId();
        this.clientSecret = Optional.ofNullable(config.getClientSecret());

        log.info("Keycloak authenticator configured with token endpoint: %s", tokenEndpoint);
    }

    public TokenResponse authenticate(String username, String password)
    {
        StringBuilder body = new StringBuilder();
        body.append("grant_type=password");
        body.append("&client_id=").append(urlEncode(clientId));
        clientSecret.ifPresent(secret -> body.append("&client_secret=").append(urlEncode(secret)));
        body.append("&username=").append(urlEncode(username));
        body.append("&password=").append(urlEncode(password));
        body.append("&scope=openid");

        log.debug("Authenticating user '%s' against Keycloak", username);

        Request request = preparePost()
                .setUri(tokenEndpoint)
                .setHeader("Content-Type", "application/x-www-form-urlencoded")
                .setBodyGenerator(createStaticBodyGenerator(body.toString(), StandardCharsets.UTF_8))
                .build();

        return httpClient.execute(request, new TokenResponseHandler());
    }

    /**
     * Refresh an access token using a refresh token.
     */
    public TokenResponse refreshToken(String refreshToken)
    {
        StringBuilder body = new StringBuilder();
        body.append("grant_type=refresh_token");
        body.append("&client_id=").append(urlEncode(clientId));
        clientSecret.ifPresent(secret -> body.append("&client_secret=").append(urlEncode(secret)));
        body.append("&refresh_token=").append(urlEncode(refreshToken));

        log.debug("Refreshing access token via Keycloak");

        Request request = preparePost()
                .setUri(tokenEndpoint)
                .setHeader("Content-Type", "application/x-www-form-urlencoded")
                .setBodyGenerator(createStaticBodyGenerator(body.toString(), StandardCharsets.UTF_8))
                .build();

        return httpClient.execute(request, new TokenResponseHandler());
    }

    private static String urlEncode(String value)
    {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static TokenResponse parseTokenResponse(String json)
    {
        String accessToken = extractString(ACCESS_TOKEN_PATTERN, json, "access_token");
        String tokenType = extractString(TOKEN_TYPE_PATTERN, json, "token_type");
        int expiresIn = extractInt(EXPIRES_IN_PATTERN, json, "expires_in");
        String refreshToken = extractStringOptional(REFRESH_TOKEN_PATTERN, json);

        return new TokenResponse(accessToken, tokenType, expiresIn, refreshToken);
    }

    private static String extractString(Pattern pattern, String json, String fieldName)
    {
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        throw new RuntimeException("Missing required field in Keycloak response: " + fieldName);
    }

    private static String extractStringOptional(Pattern pattern, String json)
    {
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private static int extractInt(Pattern pattern, String json, String fieldName)
    {
        Matcher matcher = pattern.matcher(json);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        throw new RuntimeException("Missing required field in Keycloak response: " + fieldName);
    }

    private static class TokenResponseHandler
            implements ResponseHandler<TokenResponse, RuntimeException>
    {
        @Override
        public TokenResponse handleException(Request request, Exception exception)
        {
            throw new RuntimeException("Keycloak authentication request failed", exception);
        }

        @Override
        public TokenResponse handle(Request request, Response response)
        {
            int statusCode = response.getStatusCode();
            log.debug("Keycloak token endpoint returned status %d", statusCode);

            if (statusCode == HttpStatus.OK.code()) {
                try {
                    byte[] bytes = response.getInputStream().readAllBytes();
                    String json = new String(bytes, StandardCharsets.UTF_8);
                    return parseTokenResponse(json);
                }
                catch (IOException e) {
                    throw new RuntimeException("Failed to read Keycloak response", e);
                }
            }

            if (statusCode == HttpStatus.UNAUTHORIZED.code() || statusCode == HttpStatus.BAD_REQUEST.code()) {
                log.debug("Authentication failed: invalid credentials");
                throw new KeycloakAuthenticationException("Invalid username or password");
            }

            throw new RuntimeException(format("Unexpected response from Keycloak: %d", statusCode));
        }
    }

    public static class TokenResponse
    {
        private final String accessToken;
        private final String tokenType;
        private final int expiresIn;
        private final String refreshToken;

        public TokenResponse(String accessToken, String tokenType, int expiresIn, String refreshToken)
        {
            this.accessToken = accessToken;
            this.tokenType = tokenType;
            this.expiresIn = expiresIn;
            this.refreshToken = refreshToken;
        }

        public String getAccessToken()
        {
            return accessToken;
        }

        public String getTokenType()
        {
            return tokenType;
        }

        public int getExpiresIn()
        {
            return expiresIn;
        }

        public String getRefreshToken()
        {
            return refreshToken;
        }
    }

    public static class KeycloakAuthenticationException
            extends RuntimeException
    {
        public KeycloakAuthenticationException(String message)
        {
            super(message);
        }
    }
}
