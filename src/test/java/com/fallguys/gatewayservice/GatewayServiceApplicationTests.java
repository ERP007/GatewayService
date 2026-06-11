package com.fallguys.gatewayservice;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;

@SpringBootTest
@Import(TestOAuth2ClientConfig.class)
class GatewayServiceApplicationTests {

    @Test
    void contextLoads() {
    }

}
