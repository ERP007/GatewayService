package com.fallguys.gatewayservice.infrastructure.security;

import com.fallguys.gatewayservice.controller.PasswordChangeController;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.net.URI;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class SecurityConfig {

    private static final String AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";
    private static final String UPDATE_PASSWORD_ACTION = "UPDATE_PASSWORD";
    private static final String DEFAULT_FRONTEND_ORIGIN = "http://localhost:5173";

    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler,
            AuthenticationFailureHandler oauth2AuthenticationFailureHandler,
            OAuth2AuthorizationRequestResolver oauth2AuthorizationRequestResolver
    ) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                "/login/**",
                                "/oauth2/**",
                                "/error"
                        ).permitAll()
                        .anyRequest().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestResolver(oauth2AuthorizationRequestResolver)
                        )
                        .successHandler(oauth2AuthenticationSuccessHandler)
                        .failureHandler(oauth2AuthenticationFailureHandler)
                )
                .oauth2Client(Customizer.withDefaults())
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler(
            @Value("${app.frontend-base-url}") String frontendBaseUrl
    ) {
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setRequestCache(new HttpSessionRequestCache());
        successHandler.setDefaultTargetUrl(frontendBaseUrl);
        return (request, response, authentication) -> {
            String passwordChangeTarget = (String) request.getSession()
                    .getAttribute(PasswordChangeController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE);

            if (passwordChangeTarget != null) {
                // UPDATE_PASSWORD 완료 후에는 일반 SavedRequest보다 비밀번호 변경을 시작한 React 화면으로 우선 복귀한다.
                request.getSession().removeAttribute(PasswordChangeController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE);
                response.sendRedirect(passwordChangeTarget);
                return;
            }

            successHandler.onAuthenticationSuccess(request, response, authentication);
        };
    }

    @Bean
    public AuthenticationFailureHandler oauth2AuthenticationFailureHandler(
            @Value("${app.frontend-base-url}") String frontendBaseUrl
    ) {
        SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler(frontendBaseUrl);
        return (request, response, exception) -> {
            String passwordChangeTarget = (String) request.getSession()
                    .getAttribute(PasswordChangeController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE);

            if (passwordChangeTarget != null) {
                // 사용자가 Required Action을 취소하거나 실패해도 React가 마이페이지에서 후속 안내를 처리할 수 있게 한다.
                request.getSession().removeAttribute(PasswordChangeController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE);
                response.sendRedirect(passwordChangeTarget);
                return;
            }

            failureHandler.onAuthenticationFailure(request, response, exception);
        };
    }

    @Bean
    public OAuth2AuthorizationRequestResolver oauth2AuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository
    ) {
        DefaultOAuth2AuthorizationRequestResolver delegate = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository,
                AUTHORIZATION_REQUEST_BASE_URI
        );

        return new OAuth2AuthorizationRequestResolver() {
            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
                return customizeAuthorizationRequest(delegate.resolve(request), request);
            }

            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
                return customizeAuthorizationRequest(delegate.resolve(request, clientRegistrationId), request);
            }
        };
    }

    @Bean
    public OAuth2AuthorizedClientManager authorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientRepository authorizedClientRepository
    ) {
        OAuth2AuthorizedClientProvider authorizedClientProvider = OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken()
                .build();
        DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
                clientRegistrationRepository,
                authorizedClientRepository
        );
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);
        return authorizedClientManager;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.allowed-origins:${app.frontend-base-url:" + DEFAULT_FRONTEND_ORIGIN + "}}")
            String corsAllowedOrigins
    ) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(corsAllowedOrigins(corsAllowedOrigins));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    private OAuth2AuthorizationRequest customizeAuthorizationRequest(
            OAuth2AuthorizationRequest authorizationRequest,
            HttpServletRequest request
    ) {
        if (authorizationRequest == null || !UPDATE_PASSWORD_ACTION.equals(request.getParameter("kc_action"))) {
            return authorizationRequest;
        }

        // Keycloak은 authorization request의 kc_action 파라미터를 보고 UPDATE_PASSWORD Required Action을 실행한다.
        Map<String, Object> additionalParameters = new LinkedHashMap<>(
                authorizationRequest.getAdditionalParameters()
        );
        additionalParameters.put("kc_action", UPDATE_PASSWORD_ACTION);

        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .additionalParameters(additionalParameters)
                .build();
    }

    private List<String> corsAllowedOrigins(String configuredOrigins) {
        if (configuredOrigins == null || configuredOrigins.isBlank()) {
            return List.of(DEFAULT_FRONTEND_ORIGIN);
        }

        List<String> allowedOrigins = Arrays.stream(configuredOrigins.split(","))
                .map(String::trim)
                .filter(origin -> !origin.isBlank())
                .map(this::toOrigin)
                .filter(origin -> origin != null)
                .distinct()
                .toList();

        if (allowedOrigins.isEmpty()) {
            return List.of(DEFAULT_FRONTEND_ORIGIN);
        }
        return allowedOrigins;
    }

    private String toOrigin(String configuredOrigin) {
        try {
            URI originUri = URI.create(configuredOrigin);
            if (originUri.getScheme() == null || originUri.getAuthority() == null) {
                return null;
            }
            return originUri.getScheme() + "://" + originUri.getAuthority();
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
