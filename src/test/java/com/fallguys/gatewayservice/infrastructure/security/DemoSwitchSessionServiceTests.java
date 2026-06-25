package com.fallguys.gatewayservice.infrastructure.security;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.FindByIndexNameSessionRepository;

import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class DemoSwitchSessionServiceTests {

    private static final Instant ISSUED_AT = Instant.parse("2026-06-25T09:00:00Z");
    private static final Instant EXPIRES_AT = Instant.parse("2026-06-25T09:30:00Z");

    private final OAuth2AuthorizedClientRepository authorizedClientRepository =
            mock(OAuth2AuthorizedClientRepository.class);
    private final DemoSwitchSessionService service = new DemoSwitchSessionService(
            new InMemoryClientRegistrationRepository(clientRegistration()),
            authorizedClientRepository
    );

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void replaceSessionStoresAuthenticationAndAuthorizedClient() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.getSession(true);
        DemoSwitchTokenResponse tokenResponse = tokenResponse(
                accessToken("target-sub", "BRANCH_MANAGER"),
                idToken("target-sub")
        );

        String principalName = service.replaceSession(tokenResponse, request, response);

        assertThat(principalName).isEqualTo("target-sub");
        HttpSession session = request.getSession(false);
        assertThat(session).isNotNull();
        assertThat(session.getAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME))
                .isEqualTo("target-sub");

        SecurityContext securityContext = (SecurityContext) session.getAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY
        );
        assertThat(securityContext).isNotNull();
        assertThat(securityContext.getAuthentication())
                .isInstanceOf(OAuth2AuthenticationToken.class);
        OAuth2AuthenticationToken authentication = (OAuth2AuthenticationToken) securityContext.getAuthentication();
        assertThat(authentication.getName()).isEqualTo("target-sub");
        assertThat(authentication.getPrincipal()).isInstanceOf(OidcUser.class);
        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
        assertThat(oidcUser.getIdToken().getTokenValue()).isEqualTo(tokenResponse.idTokenValue());
        assertThat(authentication.getAuthorities())
                .extracting("authority")
                .contains("ROLE_BRANCH_MANAGER", "BRANCH_MANAGER", "SCOPE_openid");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);

        verify(authorizedClientRepository).saveAuthorizedClient(
                any(OAuth2AuthorizedClient.class),
                eq(authentication),
                eq(request),
                eq(response)
        );
    }

    @Test
    void replaceSessionRejectsAccessTokenWithoutSubject() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        DemoSwitchTokenResponse tokenResponse = tokenResponse(accessToken(null, "BRANCH_MANAGER"), idToken("target-sub"));

        assertThatThrownBy(() -> service.replaceSession(tokenResponse, request, response))
                .isInstanceOf(DemoSwitchTokenException.class)
                .hasMessage("Demo switch token is missing sub claim.");
    }

    @Test
    void replaceSessionRejectsMissingIdToken() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        DemoSwitchTokenResponse tokenResponse = tokenResponse(accessToken("target-sub", "BRANCH_MANAGER"), null);

        assertThatThrownBy(() -> service.replaceSession(tokenResponse, request, response))
                .isInstanceOf(DemoSwitchTokenException.class)
                .hasMessage("Demo switch token response is missing id_token.");
    }

    private DemoSwitchTokenResponse tokenResponse(String accessTokenValue, String idTokenValue) {
        return new DemoSwitchTokenResponse(
                "keycloak",
                accessTokenValue,
                "refresh-token",
                idTokenValue,
                "Bearer",
                ISSUED_AT,
                EXPIRES_AT,
                Set.of("openid", "profile", "email")
        );
    }

    private String accessToken(String sub, String userRole) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issueTime(java.util.Date.from(ISSUED_AT))
                .expirationTime(java.util.Date.from(EXPIRES_AT))
                .claim("user_role", userRole);
        if (sub != null) {
            builder.subject(sub);
        }
        return new PlainJWT(builder.build()).serialize();
    }

    private String idToken(String sub) {
        return new PlainJWT(new JWTClaimsSet.Builder()
                .subject(sub)
                .issueTime(java.util.Date.from(ISSUED_AT))
                .expirationTime(java.util.Date.from(EXPIRES_AT))
                .build()).serialize();
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
