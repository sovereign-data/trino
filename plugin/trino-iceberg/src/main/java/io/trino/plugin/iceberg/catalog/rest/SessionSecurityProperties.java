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
package io.trino.plugin.iceberg.catalog.rest;

import com.google.common.collect.ImmutableMap;
import org.apache.iceberg.rest.auth.AuthProperties;
import org.apache.iceberg.rest.auth.OAuth2Properties;

import java.util.Map;

/**
 * Security properties for session-based authentication.
 * Sets up OAuth2 authentication handlers but without static credentials,
 * relying on the session's extraCredentials (containing user's JWT token)
 * to be used for Bearer authentication.
 */
public class SessionSecurityProperties
        implements SecurityProperties
{
    private static final Map<String, String> PROPERTIES = ImmutableMap.of(
            AuthProperties.AUTH_TYPE, AuthProperties.AUTH_TYPE_OAUTH2,
            OAuth2Properties.TOKEN_REFRESH_ENABLED, "false",
            OAuth2Properties.TOKEN_EXCHANGE_ENABLED, "false");

    @Override
    public Map<String, String> get()
    {
        return PROPERTIES;
    }
}
