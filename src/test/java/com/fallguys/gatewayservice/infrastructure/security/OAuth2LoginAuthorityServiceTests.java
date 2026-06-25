package com.fallguys.gatewayservice.infrastructure.security;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuth2LoginAuthorityServiceTests {

    private final OAuth2AuthorizedClientRepository authorizedClientRepository =
            mock(OAuth2AuthorizedClientRepository.class);
    private final OAuth2LoginAuthorityService service = new OAuth2LoginAuthorityService(authorizedClientRepository);

    @Test
    void enhanceAddsUserRoleAuthoritiesFromAccessToken() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        OAuth2AuthenticationToken authentication = authentication();
        when(authorizedClientRepository.loadAuthorizedClient(
                eq("keycloak"),
                eq(authentication),
                eq(request)
        )).thenReturn(authorizedClient("HQ_MANAGER"));

        Authentication enhanced = service.enhance(authentication, request);

        assertThat(enhanced).isInstanceOf(OAuth2AuthenticationToken.class);
        assertThat(enhanced.getAuthorities())
                .extracting("authority")
                .contains("SCOPE_openid", "HQ_MANAGER", "ROLE_HQ_MANAGER");
        assertThat(((OAuth2AuthenticationToken) enhanced).getPrincipal().getAuthorities())
                .extracting("authority")
                .contains("HQ_MANAGER", "ROLE_HQ_MANAGER");
        assertThat(enhanced.getName()).isEqualTo("keycloak-sub-001");
    }

    @Test
    void enhanceReturnsOriginalAuthenticationWhenAccessTokenHasNoUserRole() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        OAuth2AuthenticationToken authentication = authentication();
        when(authorizedClientRepository.loadAuthorizedClient(
                eq("keycloak"),
                eq(authentication),
                eq(request)
        )).thenReturn(authorizedClient(null));

        Authentication enhanced = service.enhance(authentication, request);

        assertThat(enhanced).isSameAs(authentication);
    }

    private OAuth2AuthenticationToken authentication() {
        OAuth2User principal = new DefaultOAuth2User(
                Set.of(new SimpleGrantedAuthority("SCOPE_openid")),
                Map.of("sub", "keycloak-sub-001"),
                "sub"
        );
        return new OAuth2AuthenticationToken(
                principal,
                principal.getAuthorities(),
                "keycloak"
        );
    }

    private OAuth2AuthorizedClient authorizedClient(String userRole) {
        Instant issuedAt = Instant.parse("2026-06-25T09:00:00Z");
        Instant expiresAt = Instant.parse("2026-06-25T09:30:00Z");
        return new OAuth2AuthorizedClient(
                clientRegistration(),
                "keycloak-sub-001",
                new OAuth2AccessToken(
                        OAuth2AccessToken.TokenType.BEARER,
                        accessToken(userRole),
                        issuedAt,
                        expiresAt,
                        Set.of("openid")
                )
        );
    }

    private String accessToken(String userRole) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject("keycloak-sub-001");
        if (userRole != null) {
            builder.claim("user_role", userRole);
        }
        return new PlainJWT(builder.build()).serialize();
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
}
