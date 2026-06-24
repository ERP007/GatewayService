package com.fallguys.gatewayservice;

import com.fallguys.gatewayservice.controller.AuthController;
import com.fallguys.gatewayservice.controller.OAuth2TokenDebugController;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "eureka.client.enabled=false",
        "app.frontend-base-url=https://frontend.erp007.xyz/app",
        "app.debug.oauth2-token-enabled=true",
        "app.cors.allowed-origins=https://app.erp007.xyz,https://admin.erp007.xyz/admin"
})
@AutoConfigureMockMvc
@Import(TestOAuth2ClientConfig.class)
class SecurityFlowTests {

    private static final String FRONTEND_BASE_URL = "https://frontend.erp007.xyz/app";
    private static final String APP_ORIGIN = "https://app.erp007.xyz";
    private static final String ADMIN_ORIGIN = "https://admin.erp007.xyz";
    private static final String KEYCLOAK_LOGOUT_URL =
            "https://auth.example.test/realms/master/protocol/openid-connect/logout"
                    + "?client_id=erp-client"
                    + "&post_logout_redirect_uri=" + FRONTEND_BASE_URL;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler oauth2AuthenticationFailureHandler;

    @Autowired
    private OAuth2AuthorizationRequestResolver oauth2AuthorizationRequestResolver;

    @Autowired
    private CorsConfigurationSource corsConfigurationSource;

    @Test
    void unauthenticatedApiRequestReturnsUnauthorizedWithoutKeycloakRedirect() throws Exception {
        mockMvc.perform(get("/api/users/session"))
                .andExpect(status().isUnauthorized())
                .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl()).isNull());
    }

    @Test
    void invalidBearerApiRequestReturnsUnauthorizedWithoutKeycloakRedirect() throws Exception {
        mockMvc.perform(get("/api/users").header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl()).isNull());
    }

    @Test
    void unauthenticatedSwaggerRequestsDoNotRedirectToOauth2Login() throws Exception {
        List<String> publicDocumentationPaths = List.of(
                "/api/inventory/swagger-ui/index.html",
                "/api/inventory/v3/api-docs"
        );

        for (String path : publicDocumentationPaths) {
            mockMvc.perform(get(path))
                    .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl()).isNull())
                    .andExpect(result -> {
                        int status = result.getResponse().getStatus();
                        assertThat(status < 300 || status >= 400).isTrue();
                    });
        }
    }

    @Test
    void unauthenticatedHealthRequestsDoNotRedirectToOauth2Login() throws Exception {
        mockMvc.perform(get("/api/procurement-orders/health"))
                .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl()).isNull())
                .andExpect(result -> {
                    int status = result.getResponse().getStatus();
                    assertThat(status < 300 || status >= 400).isTrue();
                });
    }

    @Test
    void gatewayHealthRequestDoesNotRequireAuthentication() throws Exception {
        mockMvc.perform(get("/api/gateway/health"))
                .andExpect(status().isOk())
                .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl()).isNull());
    }

    @Test
    void authLoginEndpointStartsKeycloakLogin() throws Exception {
        mockMvc.perform(get("/api/auth/login"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/oauth2/authorization/keycloak"));
    }

    @Test
    void authLoginEndpointCanForceKeycloakLoginPrompt() throws Exception {
        mockMvc.perform(get("/api/auth/login").queryParam("prompt", "login"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/oauth2/authorization/keycloak?prompt=login"));
    }

    @Test
    void unauthenticatedDebugTokenRequestReturnsUnauthorizedWithoutKeycloakRedirect() throws Exception {
        assertThat(applicationContext.getBeanNamesForType(OAuth2TokenDebugController.class)).isNotEmpty();

        mockMvc.perform(get("/api/debug/oauth2-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl()).isNull());
    }

    @Test
    void loginSuccessWithoutSavedRequestRedirectsToFrontendEntryPoint() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");

        oauth2AuthenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getRedirectedUrl()).isEqualTo(FRONTEND_BASE_URL);
        assertThat(request.getSession().getAttribute(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME))
                .isEqualTo("user");
    }

    @Test
    void passwordChangeEndpointStartsKeycloakUpdatePasswordAction() throws Exception {
        mockMvc.perform(get("/api/auth/password-change").with(user("hq001")))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/oauth2/authorization/keycloak?kc_action=UPDATE_PASSWORD"))
                .andExpect(request().sessionAttribute(
                        AuthController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE,
                        FRONTEND_BASE_URL + "/mypage"
                ));
    }

    @Test
    void logoutWithoutAuthenticationRedirectsToKeycloakLogout() throws Exception {
        mockMvc.perform(get("/api/auth/logout"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(KEYCLOAK_LOGOUT_URL));
    }

    @Test
    void logoutWithAuthenticationClearsSessionAndCookies() throws Exception {
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("existing", "value");

        mockMvc.perform(get("/api/auth/logout")
                        .session(session)
                        .cookie(
                                new Cookie("JSESSIONID", "gateway-session"),
                                new Cookie("GATEWAY_SESSION", "gateway-spring-session"),
                                new Cookie("SESSION", "spring-session")
                        )
                        .with(oidcLogin()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(FRONTEND_BASE_URL))
                .andExpect(cookie().maxAge("JSESSIONID", 0))
                .andExpect(cookie().maxAge("GATEWAY_SESSION", 0))
                .andExpect(cookie().maxAge("SESSION", 0));

        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    void corsAllowedOriginsUseConfiguredCorsOrigins() {
        MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/api/users/session");
        request.addHeader("Origin", APP_ORIGIN);

        CorsConfiguration corsConfiguration = corsConfigurationSource.getCorsConfiguration(request);

        assertThat(corsConfiguration).isNotNull();
        assertThat(corsConfiguration.getAllowedOrigins()).containsExactly(APP_ORIGIN, ADMIN_ORIGIN);
    }

    @Test
    void keycloakAuthorizationRequestIncludesUpdatePasswordAction() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorization/keycloak");
        request.setServletPath("/oauth2/authorization/keycloak");
        request.addParameter("kc_action", "UPDATE_PASSWORD");

        OAuth2AuthorizationRequest authorizationRequest = oauth2AuthorizationRequestResolver.resolve(request);

        assertThat(authorizationRequest).isNotNull();
        assertThat(authorizationRequest.getAdditionalParameters())
                .containsEntry("kc_action", "UPDATE_PASSWORD");
    }

    @Test
    void keycloakAuthorizationRequestIncludesLoginPrompt() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/authorization/keycloak");
        request.setServletPath("/oauth2/authorization/keycloak");
        request.addParameter("prompt", "login");

        OAuth2AuthorizationRequest authorizationRequest = oauth2AuthorizationRequestResolver.resolve(request);

        assertThat(authorizationRequest).isNotNull();
        assertThat(authorizationRequest.getAdditionalParameters())
                .containsEntry("prompt", "login");
    }

    @Test
    void loginSuccessAfterPasswordChangeRedirectsToMyPage() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(
                AuthController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE,
                FRONTEND_BASE_URL + "/mypage"
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");

        oauth2AuthenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getRedirectedUrl()).isEqualTo(FRONTEND_BASE_URL + "/mypage");
        assertThat(request.getSession().getAttribute(
                AuthController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE
        )).isNull();
    }

    @Test
    void loginFailureAfterPasswordChangeRedirectsToMyPage() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(
                AuthController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE,
                FRONTEND_BASE_URL + "/mypage"
        );
        MockHttpServletResponse response = new MockHttpServletResponse();

        oauth2AuthenticationFailureHandler.onAuthenticationFailure(
                request,
                response,
                new BadCredentialsException("password change cancelled")
        );

        assertThat(response.getRedirectedUrl()).isEqualTo(FRONTEND_BASE_URL + "/mypage");
        assertThat(request.getSession().getAttribute(
                AuthController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE
        )).isNull();
    }
}
