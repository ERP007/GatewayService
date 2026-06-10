package com.fallguys.gatewayservice;

import com.fallguys.gatewayservice.controller.PasswordChangeController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "eureka.client.enabled=false")
@AutoConfigureMockMvc
class SecurityFlowTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler oauth2AuthenticationFailureHandler;

    @Autowired
    private OAuth2AuthorizationRequestResolver oauth2AuthorizationRequestResolver;

    @Test
    void unauthenticatedGatewayRequestRedirectsToOauth2Login() throws Exception {
        mockMvc.perform(get("/api/users"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/oauth2/authorization/keycloak"))
                .andExpect(request().sessionAttribute("SPRING_SECURITY_SAVED_REQUEST", notNullValue()));
    }

    @Test
    void loginSuccessWithoutSavedRequestRedirectsToFrontendHome() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");

        oauth2AuthenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost:5173");
    }

    @Test
    void passwordChangeEndpointStartsKeycloakUpdatePasswordAction() throws Exception {
        mockMvc.perform(get("/auth/password-change").with(user("hq001")))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/oauth2/authorization/keycloak?kc_action=UPDATE_PASSWORD"))
                .andExpect(request().sessionAttribute(
                        PasswordChangeController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE,
                        "http://localhost:5173/mypage"
                ));
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
    void loginSuccessAfterPasswordChangeRedirectsToMyPage() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(
                PasswordChangeController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE,
                "http://localhost:5173/mypage"
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        TestingAuthenticationToken authentication = new TestingAuthenticationToken("user", "password");

        oauth2AuthenticationSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost:5173/mypage");
        assertThat(request.getSession().getAttribute(
                PasswordChangeController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE
        )).isNull();
    }

    @Test
    void loginFailureAfterPasswordChangeRedirectsToMyPage() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession().setAttribute(
                PasswordChangeController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE,
                "http://localhost:5173/mypage"
        );
        MockHttpServletResponse response = new MockHttpServletResponse();

        oauth2AuthenticationFailureHandler.onAuthenticationFailure(
                request,
                response,
                new BadCredentialsException("password change cancelled")
        );

        assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost:5173/mypage");
        assertThat(request.getSession().getAttribute(
                PasswordChangeController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE
        )).isNull();
    }
}
