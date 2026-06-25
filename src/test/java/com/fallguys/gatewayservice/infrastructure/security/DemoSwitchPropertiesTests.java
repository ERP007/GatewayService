package com.fallguys.gatewayservice.infrastructure.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class DemoSwitchPropertiesTests {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class);

    @Test
    void disabledDemoSwitchAllowsEmptyAccounts() {
        contextRunner
                .withPropertyValues("app.demo-switch.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    DemoSwitchProperties properties = context.getBean(DemoSwitchProperties.class);
                    assertThat(properties.enabled()).isFalse();
                    assertThat(properties.accounts()).isEmpty();
                });
    }

    @Test
    void enabledDemoSwitchBindsConfiguredAccount() {
        contextRunner
                .withPropertyValues(
                        "app.demo-switch.enabled=true",
                        "app.demo-switch.accounts.br001.username=br001",
                        "app.demo-switch.accounts.br001.password=secret"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    DemoSwitchProperties properties = context.getBean(DemoSwitchProperties.class);
                    assertThat(properties.enabled()).isTrue();
                    assertThat(properties.findAccount("BR001"))
                            .hasValueSatisfying(account -> {
                                assertThat(account.username()).isEqualTo("br001");
                                assertThat(account.password()).isEqualTo("secret");
                            });
                });
    }

    @Test
    void enabledDemoSwitchRejectsMissingPassword() {
        contextRunner
                .withPropertyValues(
                        "app.demo-switch.enabled=true",
                        "app.demo-switch.accounts.BR001.username=br001"
                )
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseMessage(
                                    "app.demo-switch.accounts.BR001.password must not be blank when demo switch is enabled."
                            );
                });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(DemoSwitchProperties.class)
    static class TestConfig {
    }
}
