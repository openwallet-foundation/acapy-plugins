# Keycloak with the ACA-Py OID4VCI pre-authorized code grant extension.
# Build context: oid4vc/keycloak
ARG KEYCLOAK_VERSION=26.8.0

FROM maven:3.9-eclipse-temurin-21 AS extension
WORKDIR /build
COPY extension/pom.xml .
RUN mvn -q -B dependency:go-offline
COPY extension/src src
RUN mvn -q -B package

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} AS builder
COPY --from=extension /build/target/keycloak-oid4vci-pre-auth.jar /opt/keycloak/providers/
# DPoP is on by default; client-auth-abca is experimental and must be enabled.
# Keycloak's own oid4vc-vci / oid4vc-vci-preauth-code features stay off: the
# latter registers a grant type with the same id as the extension.
ENV KC_FEATURES=client-auth-abca,dpop
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}
COPY --from=builder /opt/keycloak/ /opt/keycloak/
# start-dev re-runs the build at startup from the runtime environment, so the
# features must be set here too. Without client-auth-abca the realm import
# fails with "Invalid identity provider id [default-trust]".
ENV KC_FEATURES=client-auth-abca,dpop
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
