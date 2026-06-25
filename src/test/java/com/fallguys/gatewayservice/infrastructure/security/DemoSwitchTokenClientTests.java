package com.fallguys.gatewayservice.infrastructure.security;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class DemoSwitchTokenClientTests {

    @Test
    void issueTokenRequestsPasswordGrantAndParsesTokenResponse() {
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server = MockRestServiceServer.bindTo(restTemplate).build();
        DemoSwitchTokenClient client = new DemoSwitchTokenClient(
                new InMemoryClientRegistrationRepository(clientRegistration(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)),
                restTemplate
        );
        server.expect(once(), requestTo("https://auth.example.test/realms/master/protocol/openid-connect/token"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.AUTHORIZATION, containsString("Basic ")))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(content().string(allOf(
                        containsString("grant_type=password"),
                        containsString("client_id=erp-client"),
                        containsString("username=br001"),
                        containsString("password=p%40ss+word"),
                        containsString("scope=openid+profile+email")
                )))
                .andRespond(withSuccess("""
                        {
                          "access_token": "access-token-value",
                          "expires_in": 300,
                          "refresh_token": "refresh-token-value",
                          "id_token": "id-token-value",
                          "token_type": "Bearer",
                          "scope": "openid profile email"
                        }
                        """, MediaType.APPLICATION_JSON));

        DemoSwitchTokenResponse response = client.issueToken(new DemoSwitchProperties.Account("br001", "p@ss word"));

        assertThat(response.clientRegistrationId()).isEqualTo("keycloak");
        assertThat(response.accessTokenValue()).isEqualTo("access-token-value");
        assertThat(response.refreshTokenValue()).isEqualTo("refresh-token-value");
        assertThat(response.idTokenValue()).isEqualTo("id-token-value");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.scopes()).containsExactly("openid", "profile", "email");
        assertThat(Duration.between(response.issuedAt(), response.accessTokenExpiresAt()).getSeconds()).isEqualTo(300);
        server.verify();
    }

    @Test
    void issueTokenSendsClientSecretInFormWhenClientUsesPostAuthentication() {
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server = MockRestServiceServer.bindTo(restTemplate).build();
        DemoSwitchTokenClient client = new DemoSwitchTokenClient(
                new InMemoryClientRegistrationRepository(clientRegistration(ClientAuthenticationMethod.CLIENT_SECRET_POST)),
                restTemplate
        );
        server.expect(once(), requestTo("https://auth.example.test/realms/master/protocol/openid-connect/token"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().string(containsString("client_secret=test-secret")))
                .andRespond(withSuccess("""
                        {
                          "access_token": "access-token-value",
                          "expires_in": 300,
                          "id_token": "id-token-value"
                        }
                        """, MediaType.APPLICATION_JSON));

        DemoSwitchTokenResponse response = client.issueToken(new DemoSwitchProperties.Account("br001", "secret"));

        assertThat(response.accessTokenValue()).isEqualTo("access-token-value");
        assertThat(response.idTokenValue()).isEqualTo("id-token-value");
        assertThat(response.scopes()).containsExactlyInAnyOrder("openid", "profile", "email");
        server.verify();
    }

    @Test
    void issueTokenAlwaysRequestsOpenIdScope() {
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server = MockRestServiceServer.bindTo(restTemplate).build();
        DemoSwitchTokenClient client = new DemoSwitchTokenClient(
                new InMemoryClientRegistrationRepository(
                        clientRegistration(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, "profile", "email")
                ),
                restTemplate
        );
        server.expect(once(), requestTo("https://auth.example.test/realms/master/protocol/openid-connect/token"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().string(containsString("scope=openid+profile+email")))
                .andRespond(withSuccess("""
                        {
                          "access_token": "access-token-value",
                          "expires_in": 300,
                          "id_token": "id-token-value"
                        }
                        """, MediaType.APPLICATION_JSON));

        DemoSwitchTokenResponse response = client.issueToken(new DemoSwitchProperties.Account("br001", "secret"));

        assertThat(response.idTokenValue()).isEqualTo("id-token-value");
        assertThat(response.scopes()).containsExactlyInAnyOrder("openid", "profile", "email");
        server.verify();
    }

    @Test
    void issueTokenRejectsMissingAccessToken() {
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server = MockRestServiceServer.bindTo(restTemplate).build();
        DemoSwitchTokenClient client = new DemoSwitchTokenClient(
                new InMemoryClientRegistrationRepository(clientRegistration(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)),
                restTemplate
        );
        server.expect(once(), requestTo("https://auth.example.test/realms/master/protocol/openid-connect/token"))
                .andRespond(withSuccess("""
                        {
                          "expires_in": 300
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> client.issueToken(new DemoSwitchProperties.Account("br001", "secret")))
                .isInstanceOf(DemoSwitchTokenException.class)
                .hasMessage("Keycloak token response is missing access_token.");
        server.verify();
    }

    @Test
    void issueTokenRejectsMissingIdToken() {
        RestTemplate restTemplate = new RestTemplate();
        MockRestServiceServer server = MockRestServiceServer.bindTo(restTemplate).build();
        DemoSwitchTokenClient client = new DemoSwitchTokenClient(
                new InMemoryClientRegistrationRepository(clientRegistration(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)),
                restTemplate
        );
        server.expect(once(), requestTo("https://auth.example.test/realms/master/protocol/openid-connect/token"))
                .andRespond(withSuccess("""
                        {
                          "access_token": "access-token-value",
                          "expires_in": 300
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> client.issueToken(new DemoSwitchProperties.Account("br001", "secret")))
                .isInstanceOf(DemoSwitchTokenException.class)
                .hasMessage("Keycloak token response is missing id_token.");
        server.verify();
    }

    private ClientRegistration clientRegistration(ClientAuthenticationMethod clientAuthenticationMethod) {
        return clientRegistration(clientAuthenticationMethod, "openid", "profile", "email");
    }

    private ClientRegistration clientRegistration(ClientAuthenticationMethod clientAuthenticationMethod, String... scopes) {
        return ClientRegistration.withRegistrationId("keycloak")
                .clientId("erp-client")
                .clientSecret("test-secret")
                .clientAuthenticationMethod(clientAuthenticationMethod)
                .clientName("keycloak")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(scopes)
                .authorizationUri("https://auth.example.test/realms/master/protocol/openid-connect/auth")
                .tokenUri("https://auth.example.test/realms/master/protocol/openid-connect/token")
                .jwkSetUri("https://auth.example.test/realms/master/protocol/openid-connect/certs")
                .userInfoUri("https://auth.example.test/realms/master/protocol/openid-connect/userinfo")
                .userNameAttributeName("sub")
                .build();
    }
}
