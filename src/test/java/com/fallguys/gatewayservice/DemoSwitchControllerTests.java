package com.fallguys.gatewayservice;

import com.fallguys.gatewayservice.infrastructure.security.DemoSwitchProperties;
import com.fallguys.gatewayservice.infrastructure.security.DemoSwitchTokenClient;
import com.fallguys.gatewayservice.infrastructure.security.DemoSwitchTokenException;
import com.fallguys.gatewayservice.infrastructure.security.DemoSwitchTokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "eureka.client.enabled=false",
        "app.demo-switch.enabled=true",
        "app.demo-switch.accounts.ADMIN.username=admin002",
        "app.demo-switch.accounts.ADMIN.password=admin-password",
        "app.demo-switch.accounts.HQ001.username=hq001",
        "app.demo-switch.accounts.HQ001.password=hq-password",
        "app.demo-switch.accounts.BR001.username=br001",
        "app.demo-switch.accounts.BR001.password=br-password"
})
@AutoConfigureMockMvc
@Import({
        TestOAuth2ClientConfig.class,
        DemoSwitchControllerTests.DemoSwitchTokenClientTestConfig.class
})
class DemoSwitchControllerTests {

    private static final Instant ACCESS_TOKEN_EXPIRES_AT = Instant.parse("2026-06-25T09:30:00Z");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private DemoSwitchTokenClient demoSwitchTokenClient;

    @BeforeEach
    void setUp() {
        reset(demoSwitchTokenClient);
        when(demoSwitchTokenClient.issueToken(any())).thenReturn(new DemoSwitchTokenResponse(
                "keycloak",
                "access-token",
                "refresh-token",
                "id-token",
                "Bearer",
                Instant.parse("2026-06-25T09:00:00Z"),
                ACCESS_TOKEN_EXPIRES_AT,
                Set.of("openid", "profile", "email")
        ));
    }

    @Test
    void switchAccountRequiresAuthentication() throws Exception {
        mockMvc.perform(post("/api/auth/demo/switch-account")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"employeeNo":"BR001"}
                                """))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void switchAccountRequiresSwitcherAuthority() throws Exception {
        mockMvc.perform(post("/api/auth/demo/switch-account")
                        .with(user("staff").roles("USER"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"employeeNo":"BR001"}
                                """))
                .andExpect(status().isForbidden());
    }

    @Test
    void switchAccountAcceptsHqAuthority() throws Exception {
        mockMvc.perform(post("/api/auth/demo/switch-account")
                        .with(user("hq001").roles("HQ_MANAGER"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"employeeNo":"BR001"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.employeeNo").value("BR001"))
                .andExpect(jsonPath("$.username").value("br001"))
                .andExpect(jsonPath("$.accessTokenExpiresAt").value("2026-06-25T09:30:00Z"));
    }

    @Test
    void switchAccountAcceptsBranchAuthority() throws Exception {
        mockMvc.perform(post("/api/auth/demo/switch-account")
                        .with(user("br001").roles("BRANCH_MANAGER"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"employeeNo":"HQ001"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.employeeNo").value("HQ001"))
                .andExpect(jsonPath("$.username").value("hq001"))
                .andExpect(jsonPath("$.accessTokenExpiresAt").value("2026-06-25T09:30:00Z"));
    }

    @Test
    void switchAccountRejectsUnknownDemoAccount() throws Exception {
        mockMvc.perform(post("/api/auth/demo/switch-account")
                        .with(user("admin").roles("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"employeeNo":"BR999"}
                                """))
                .andExpect(status().isNotFound());
    }

    @Test
    void switchAccountAcceptsAllowedDemoAccount() throws Exception {
        mockMvc.perform(post("/api/auth/demo/switch-account")
                        .with(user("admin").roles("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"employeeNo":"br001"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.employeeNo").value("BR001"))
                .andExpect(jsonPath("$.username").value("br001"))
                .andExpect(jsonPath("$.accessTokenExpiresAt").value("2026-06-25T09:30:00Z"));

        verify(demoSwitchTokenClient).issueToken(new DemoSwitchProperties.Account("br001", "br-password"));
    }

    @Test
    void switchAccountReturnsBadGatewayWhenTokenIssueFails() throws Exception {
        doThrow(new DemoSwitchTokenException("Keycloak token request failed."))
                .when(demoSwitchTokenClient)
                .issueToken(any());

        mockMvc.perform(post("/api/auth/demo/switch-account")
                        .with(user("admin").roles("ADMIN"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"employeeNo":"BR001"}
                                """))
                .andExpect(status().isBadGateway());
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class DemoSwitchTokenClientTestConfig {

        @Bean
        @Primary
        DemoSwitchTokenClient demoSwitchTokenClient() {
            return mock(DemoSwitchTokenClient.class);
        }
    }
}
