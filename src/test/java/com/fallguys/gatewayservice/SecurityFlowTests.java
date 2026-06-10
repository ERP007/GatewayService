package com.fallguys.gatewayservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.notNullValue;
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
}
