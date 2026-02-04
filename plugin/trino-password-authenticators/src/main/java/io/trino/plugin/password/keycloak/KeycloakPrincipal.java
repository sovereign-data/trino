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

import io.trino.spi.security.CredentialCarryingPrincipal;

import java.util.Map;
import java.util.Objects;

import static java.util.Objects.requireNonNull;

/**
 * A Principal that carries extra credentials (e.g., OAuth tokens) from authentication.
 * Implements CredentialCarryingPrincipal so the server-side can extract and propagate
 * these credentials to the session's extra credentials.
 */
public class KeycloakPrincipal
        implements CredentialCarryingPrincipal
{
    private final String name;
    private final Map<String, String> extraCredentials;

    public KeycloakPrincipal(String name, Map<String, String> extraCredentials)
    {
        this.name = requireNonNull(name, "name is null");
        this.extraCredentials = Map.copyOf(requireNonNull(extraCredentials, "extraCredentials is null"));
    }

    @Override
    public String getName()
    {
        return name;
    }

    @Override
    public Map<String, String> getExtraCredentials()
    {
        return extraCredentials;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        KeycloakPrincipal that = (KeycloakPrincipal) o;
        return Objects.equals(name, that.name);
    }

    @Override
    public int hashCode()
    {
        return Objects.hash(name);
    }

    @Override
    public String toString()
    {
        return name;
    }
}
