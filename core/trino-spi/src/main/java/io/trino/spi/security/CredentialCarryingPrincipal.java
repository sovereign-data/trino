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
package io.trino.spi.security;

import java.security.Principal;
import java.util.Map;

/**
 * A Principal that carries additional credentials that should be propagated
 * to connectors via the session's extra credentials.
 * <p>
 * This is typically used by authenticators that obtain tokens (e.g., OAuth tokens)
 * during authentication that need to be forwarded to downstream services
 * (e.g., Iceberg REST catalog with user-level OAuth).
 */
public interface CredentialCarryingPrincipal
        extends Principal
{
    /**
     * Returns credentials that should be added to the session's extra credentials.
     * <p>
     * The returned map keys are credential names, and values are the credential values.
     * These will be merged with any other extra credentials in the session.
     *
     * @return immutable map of credential name to credential value
     */
    Map<String, String> getExtraCredentials();
}
