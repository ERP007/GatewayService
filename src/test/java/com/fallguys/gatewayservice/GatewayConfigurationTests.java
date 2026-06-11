package com.fallguys.gatewayservice;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.server.mvc.config.FilterProperties;
import org.springframework.cloud.gateway.server.mvc.config.GatewayMvcProperties;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = "eureka.client.enabled=false")
@Import(TestOAuth2ClientConfig.class)
class GatewayConfigurationTests {

    @Autowired
    private GatewayMvcProperties gatewayMvcProperties;

    @Test
    void userRouteRelaysAuthorizedClientAccessToken() {
        assertThat(gatewayMvcProperties.getRoutes())
                .singleElement()
                .satisfies(route -> {
                    assertThat(route.getId()).isEqualTo("user-service");
                    assertThat(route.getUri()).hasScheme("http");
                    assertThat(route.getPredicates())
                            .singleElement()
                            .satisfies(predicate -> assertThat(predicate.getName()).isEqualTo("Path"));
                    assertThat(route.getPredicates().getFirst().getArgs())
                            .containsValue("/api/users/**");
                    assertThat(route.getFilters())
                            .extracting(FilterProperties::getName)
                            .containsExactly("TokenRelay", "StripPrefix");
                    assertThat(route.getFilters().get(1).getArgs())
                            .containsValue("1");
                });
    }
}
