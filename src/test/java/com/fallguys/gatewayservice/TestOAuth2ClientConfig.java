package com.fallguys.gatewayservice;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;

import static org.mockito.Mockito.mock;

@TestConfiguration(proxyBeanMethods = false)
class TestOAuth2ClientConfig {

    @Bean
    ClientRegistrationRepository clientRegistrationRepository() {
        ClientRegistration keycloak = ClientRegistration.withRegistrationId("keycloak")
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

        return new InMemoryClientRegistrationRepository(keycloak);
    }

    @Bean
    @SuppressWarnings("unchecked")
    FindByIndexNameSessionRepository<Session> sessionRepository() {
        return mock(FindByIndexNameSessionRepository.class);
    }
}
