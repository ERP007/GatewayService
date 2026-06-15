package com.fallguys.gatewayservice;

import com.fallguys.gatewayservice.controller.OAuth2TokenDebugController;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class OAuth2TokenDebugControllerTests {

    private final OAuth2TokenDebugController controller = new OAuth2TokenDebugController();

    @Test
    void tokenResponseIncludesAccessTokenAndRefreshTokenValues() {
        Instant issuedAt = Instant.parse("2026-06-13T00:00:00Z");
        Instant expiresAt = Instant.parse("2026-06-13T01:00:00Z");
        String tokenValue = new PlainJWT(new JWTClaimsSet.Builder()
                .subject("br001")
                .claim("user_role", "BRANCH_STAFF")
                .claim("tenancy_type", "BRANCH")
                .claim("tenancy_code", "WH-BR-001")
                .claim("employee_no", "br001")
                .claim("preferred_username", "br001")
                .claim("name", "branch staff")
                .claim("position", "staff")
                .claim("email", "br001@example.com")
                .build()).serialize();
        OAuth2AuthorizedClient client = authorizedClient(
                new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        tokenValue,
                        issuedAt,
                        expiresAt,
                        Set.of("openid", "profile", "email")
                ),
                new OAuth2RefreshToken("refresh-token-secret", issuedAt, expiresAt)
        );

        ResponseEntity<Map<String, Object>> response = controller.token(client);

        assertThat(response.getHeaders().getCacheControl()).contains("no-store");
        Map<String, Object> body = response.getBody();
        assertThat(body).isNotNull();

        Map<String, Object> accessToken = mapValue(body, "accessToken");
        assertThat(accessToken)
                .containsEntry("tokenValue", tokenValue)
                .containsEntry("tokenType", "Bearer")
                .containsEntry("userRole", "BRANCH_STAFF");

        Map<String, Object> claims = mapValue(accessToken, "claims");
        assertThat(claims)
                .containsEntry("user_role", "BRANCH_STAFF")
                .containsEntry("tenancy_type", "BRANCH")
                .containsEntry("tenancy_code", "WH-BR-001");

        Map<String, Object> refreshToken = mapValue(body, "refreshToken");
        assertThat(refreshToken)
                .containsEntry("tokenValue", "refresh-token-secret")
                .containsEntry("issuedAt", issuedAt)
                .containsEntry("expiresAt", expiresAt);
    }

    @Test
    void tokenResponseMarksNonJwtAccessTokenAsNotDecoded() {
        Instant issuedAt = Instant.parse("2026-06-13T00:00:00Z");
        OAuth2AuthorizedClient client = authorizedClient(
                new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        "opaque-access-token",
                        issuedAt,
                        issuedAt.plusSeconds(3600)
                ),
                null
        );

        ResponseEntity<Map<String, Object>> response = controller.token(client);

        Map<String, Object> accessToken = mapValue(response.getBody(), "accessToken");
        assertThat(accessToken)
                .containsEntry("tokenValue", "opaque-access-token");
        assertThat(mapValue(accessToken, "claims").get("decodeError")).isNotNull();
        assertThat(response.getBody()).containsEntry("refreshToken", null);
    }

    private OAuth2AuthorizedClient authorizedClient(
            OAuth2AccessToken accessToken,
            OAuth2RefreshToken refreshToken
    ) {
        return new OAuth2AuthorizedClient(clientRegistration(), "br001", accessToken, refreshToken);
    }

    private ClientRegistration clientRegistration() {
        return ClientRegistration.withRegistrationId("keycloak")
                .clientId("erp-client")
                .clientSecret("test-secret")
                .clientName("keycloak")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope("openid", "profile", "email")
                .authorizationUri("https://auth.example.test/realms/master/protocol/openid-connect/auth")
                .tokenUri("https://auth.example.test/realms/master/protocol/openid-connect/token")
                .jwkSetUri("https://auth.example.test/realms/master/protocol/openid-connect/certs")
                .userInfoUri("https://auth.example.test/realms/master/protocol/openid-connect/userinfo")
                .userNameAttributeName("sub")
                .build();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> mapValue(Map<String, Object> source, String key) {
        return (Map<String, Object>) source.get(key);
    }
}
