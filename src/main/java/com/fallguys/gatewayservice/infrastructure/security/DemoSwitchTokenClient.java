package com.fallguys.gatewayservice.infrastructure.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

@Component
public class DemoSwitchTokenClient {

    private static final String KEYCLOAK_REGISTRATION_ID = "keycloak";
    private static final String PASSWORD_GRANT_TYPE = "password";
    private static final String OPENID_SCOPE = "openid";

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final RestOperations restOperations;

    @Autowired
    public DemoSwitchTokenClient(ClientRegistrationRepository clientRegistrationRepository) {
        this(clientRegistrationRepository, new RestTemplate());
    }

    DemoSwitchTokenClient(
            ClientRegistrationRepository clientRegistrationRepository,
            RestOperations restOperations
    ) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.restOperations = restOperations;
    }

    public DemoSwitchTokenResponse issueToken(DemoSwitchProperties.Account account) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(KEYCLOAK_REGISTRATION_ID);
        if (clientRegistration == null) {
            throw new DemoSwitchTokenException("Keycloak client registration is not configured.");
        }

        Instant issuedAt = Instant.now();
        Set<String> requestedScopes = tokenRequestScopes(clientRegistration);
        ResponseEntity<Map<String, Object>> response;
        try {
            response = restOperations.exchange(
                    clientRegistration.getProviderDetails().getTokenUri(),
                    HttpMethod.POST,
                    tokenRequest(clientRegistration, account, requestedScopes),
                    new ParameterizedTypeReference<>() {
                    }
            );
        } catch (RestClientException e) {
            throw new DemoSwitchTokenException("Failed to issue demo switch token.", e);
        }

        return DemoSwitchTokenResponse.from(
                clientRegistration.getRegistrationId(),
                response.getBody(),
                issuedAt,
                requestedScopes
        );
    }

    private HttpEntity<MultiValueMap<String, String>> tokenRequest(
            ClientRegistration clientRegistration,
            DemoSwitchProperties.Account account,
            Set<String> requestedScopes
    ) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(java.util.List.of(MediaType.APPLICATION_JSON));

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", PASSWORD_GRANT_TYPE);
        form.add("client_id", clientRegistration.getClientId());
        form.add("username", account.username());
        form.add("password", account.password());
        form.add("scope", String.join(" ", requestedScopes));

        String clientSecret = clientRegistration.getClientSecret();
        if (clientSecret != null && !clientSecret.isBlank()) {
            if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(
                    clientRegistration.getClientAuthenticationMethod()
            )) {
                headers.setBasicAuth(clientRegistration.getClientId(), clientSecret);
            } else {
                form.add("client_secret", clientSecret);
            }
        }

        return new HttpEntity<>(form, headers);
    }

    private Set<String> tokenRequestScopes(ClientRegistration clientRegistration) {
        LinkedHashSet<String> scopes = new LinkedHashSet<>();
        scopes.add(OPENID_SCOPE);
        scopes.addAll(clientRegistration.getScopes());
        return scopes;
    }
}
