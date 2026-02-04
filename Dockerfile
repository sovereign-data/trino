# Trino with custom Keycloak password authenticator and CredentialCarryingPrincipal SPI
#
# This Dockerfile builds Trino from source because:
# 1. Custom CredentialCarryingPrincipal interface in trino-spi
# 2. Custom handling in trino-main/PasswordAuthenticator.java
# 3. Custom KeycloakAuthenticator plugin
#
# These changes allow OAuth tokens to be passed through to downstream connectors.

FROM maven:3.9-eclipse-temurin-25 AS builder

WORKDIR /trino

# Copy the entire trino source
COPY . .

# Create a minimal provisio descriptor that only includes essential plugins
RUN cat > /trino/core/trino-server-core/src/main/provisio/trino-core.xml << 'EOF'
<runtime>
    <!-- Target -->
    <archive name="${project.artifactId}-${project.version}.tar.gz" hardLinkIncludes="**/*.jar" />

    <!-- Notices -->
    <fileSet to="/">
        <directory path="${basedir}">
            <include>NOTICE</include>
            <include>README.txt</include>
        </directory>
    </fileSet>

    <!-- Launcher -->
    <artifactSet to="bin">
        <artifact id="io.airlift:launcher:tar.gz:bin:${dep.launcher.version}">
            <unpack />
        </artifact>
        <artifact id="io.airlift:launcher:tar.gz:properties:${dep.launcher.version}">
            <unpack filter="true" />
        </artifact>
    </artifactSet>

    <!-- Server -->
    <artifactSet to="lib">
        <artifact id="${project.groupId}:trino-server-main:${project.version}" />
    </artifactSet>

    <!-- Configuration Plugins -->
    <artifactSet to="secrets-plugin/keystore-secrets-plugin">
        <artifact id="io.airlift:secrets-keystore-plugin:zip:${dep.airlift.version}">
            <unpack />
        </artifact>
    </artifactSet>

    <!-- Minimal Plugins - only what we need -->
    <artifactSet to="plugin/password-authenticators">
        <artifact id="${project.groupId}:trino-password-authenticators:zip:${project.version}">
            <unpack />
        </artifact>
    </artifactSet>

</runtime>
EOF

# Step 1: Build core modules (trino-spi with CredentialCarryingPrincipal, trino-main with the check)
RUN ./mvnw clean install \
    -pl core/trino-main,core/trino-server-main \
    -am \
    -DskipTests \
    -Dair.check.skip-all=true \
    -Dmaven.javadoc.skip=true \
    -Dcheckstyle.skip=true \
    -Dforbiddenapis.skip=true \
    -Dspotbugs.skip=true \
    -Dmaven.gitcommitid.skip=true \
    -T 1C \
    --no-transfer-progress

# Step 2: Build password-authenticators plugin (has CredentialCarryingPrincipal dependency)
RUN ./mvnw install \
    -pl plugin/trino-password-authenticators \
    -DskipTests \
    -Dair.check.skip-all=true \
    -Dmaven.javadoc.skip=true \
    -Dcheckstyle.skip=true \
    -Dforbiddenapis.skip=true \
    -Dspotbugs.skip=true \
    -Dmaven.gitcommitid.skip=true \
    --no-transfer-progress

# Step 3: Build trino-server-core with minimal plugins
RUN ./mvnw install \
    -pl core/trino-server-core \
    -DskipTests \
    -Dair.check.skip-all=true \
    -Dmaven.javadoc.skip=true \
    -Dcheckstyle.skip=true \
    -Dforbiddenapis.skip=true \
    -Dspotbugs.skip=true \
    -Dmaven.gitcommitid.skip=true \
    --no-transfer-progress

# Step 4: Build iceberg plugin with all dependencies
RUN ./mvnw install \
    -pl plugin/trino-iceberg \
    -am \
    -DskipTests \
    -Dair.check.skip-all=true \
    -Dmaven.javadoc.skip=true \
    -Dcheckstyle.skip=true \
    -Dforbiddenapis.skip=true \
    -Dspotbugs.skip=true \
    -Dmaven.gitcommitid.skip=true \
    -T 1C \
    --no-transfer-progress

# Extract the server distribution
RUN mkdir -p /trino-server && \
    tar -xzf /trino/core/trino-server-core/target/trino-server-core-*-SNAPSHOT.tar.gz -C /trino-server --strip-components=1

# Stage 2: Runtime image
FROM eclipse-temurin:25-jre

# Install required packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    less \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create trino user
RUN groupadd -r trino && useradd -r -g trino trino

# Copy Trino server (includes custom SPI and main with CredentialCarryingPrincipal support)
COPY --from=builder /trino-server /usr/lib/trino

# Copy the Iceberg plugin
COPY --from=builder /trino/plugin/trino-iceberg/target/trino-iceberg-*-SNAPSHOT/ /usr/lib/trino/plugin/iceberg/

# Create necessary directories
RUN mkdir -p /data/trino /var/trino /etc/trino && \
    chown -R trino:trino /data/trino /var/trino /usr/lib/trino /etc/trino

# Set up launcher symlink
RUN ln -s /usr/lib/trino/bin/launcher /usr/bin/trino

USER trino

WORKDIR /usr/lib/trino

# Default command - use /etc/trino for config (mounted from host)
CMD ["/usr/lib/trino/bin/launcher", "run", "--etc-dir=/etc/trino", "--data-dir=/data/trino"]

# Healthcheck
HEALTHCHECK --interval=10s --timeout=5s --start-period=120s --retries=10 \
    CMD curl -sf http://localhost:8080/v1/info | grep -q '"starting":false' || exit 1
