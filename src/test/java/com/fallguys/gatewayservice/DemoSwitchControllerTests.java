package com.fallguys.gatewayservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

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
@Import(TestOAuth2ClientConfig.class)
class DemoSwitchControllerTests {

    @Autowired
    private MockMvc mockMvc;

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
                .andExpect(jsonPath("$.username").value("br001"));
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
                .andExpect(jsonPath("$.username").value("hq001"));
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
                .andExpect(jsonPath("$.username").value("br001"));
    }
}
