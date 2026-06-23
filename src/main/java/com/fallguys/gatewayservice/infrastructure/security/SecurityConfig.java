package com.fallguys.gatewayservice.infrastructure.security;

import com.fallguys.gatewayservice.controller.AuthController;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.net.URI;
import java.util.*;

@Configuration
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    // Spring Security가 Keycloak 로그인을 시작할 때 사용하는 기본 authorization endpoint prefix.
    private static final String AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";

    // Keycloak AIA(Application Initiated Action)로 비밀번호 변경 화면을 열 때 넘기는 action 값.
    private static final String UPDATE_PASSWORD_ACTION = "UPDATE_PASSWORD";

    // CORS 설정값이 비어 있을 때 로컬 React 개발 서버를 기본 허용 origin으로 사용한다.
    private static final String DEFAULT_FRONTEND_ORIGIN = "http://localhost:5173";

    private static final String[] PUBLIC_API_MATCHERS = {
            "/api/*/health",
            "/api/*/swagger-ui/**",
            "/api/*/swagger-ui.html",
            "/api/*/v3/api-docs/**"
    };

    @Bean
    OAuth2AuthorizedClientRepository oauth2AuthorizedClientRepository() {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    /*
     * OAuth2 Login 기반 세션 흐름을 조립한다.
     *
     * - API, 로그인 시작, callback, logout, 에러 endpoint를 OAuth2 Client 세션 흐름으로 보호한다.
     * - OAuth2 로그인 성공/실패 후 React로 돌아가는 handler를 연결한다.
     * - 로그아웃 시 Gateway 세션을 지우고 Keycloak SSO 로그아웃으로 보낸다.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain oauth2LoginSecurityFilterChain(
            HttpSecurity http,
            AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler,
            AuthenticationFailureHandler oauth2AuthenticationFailureHandler,
            LogoutSuccessHandler oidcLogoutSuccessHandler,
            OAuth2AuthorizationRequestResolver oauth2AuthorizationRequestResolver,
            OAuth2AuthorizedClientRepository oauth2AuthorizedClientRepository,
            @Value("${server.servlet.session.cookie.name:GATEWAY_SESSION}") String sessionCookieName
    ) throws Exception {
        http
                .securityMatcher("/api/**", "/login/**", "/oauth2/**", "/error")

                // 로그인 시작, OAuth2 callback, 로그아웃, 공개 API, 에러 페이지는 인증 없이 접근 가능해야 한다.
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                        .requestMatchers(
                                "/login/**",
                                "/oauth2/**",
                                "/api/auth/login",
                                "/api/auth/logout",
                                "/error"
                        ).permitAll()
                        .requestMatchers(PUBLIC_API_MATCHERS).permitAll()
                        .anyRequest().authenticated())

                // Keycloak 로그인 플로우. 커스텀 resolver/handler를 끼워 비밀번호 변경 AIA와 React 복귀를 처리한다.
                .oauth2Login(oauth2 -> oauth2
                        .authorizedClientRepository(oauth2AuthorizedClientRepository)
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestResolver(oauth2AuthorizationRequestResolver)
                        )
                        .successHandler(oauth2AuthenticationSuccessHandler)
                        .failureHandler(oauth2AuthenticationFailureHandler)
                )

                // 브라우저가 /api/auth/logout으로 이동하면 Gateway 세션을 정리한 뒤 Keycloak logout으로 redirect한다.
                .logout(logout -> logout
                        .logoutUrl("/api/auth/logout")
                        .logoutSuccessHandler(oidcLogoutSuccessHandler)
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID", "SESSION", sessionCookieName)
                )

                // OAuth2 Login 세션 흐름에서 authorized client 저장소를 사용할 수 있게 한다.
                .oauth2Client(oauth2 -> oauth2
                        .authorizedClientRepository(oauth2AuthorizedClientRepository)
                )
                .requestCache(cache -> cache.requestCache(new NullRequestCache()))
                // API 요청은 XHR이 Keycloak redirect를 따라가지 않도록 401로 끝낸다.
                .exceptionHandling(exception -> exception
                        .defaultAuthenticationEntryPointFor(
                                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                                request -> request.getRequestURI().startsWith(request.getContextPath() + "/api/")
                        )
                )

                // React 개발 서버에서 credentials 포함 요청을 받을 수 있게 CorsConfigurationSource bean을 적용한다.
                .cors(Customizer.withDefaults())

                // 현재 Gateway는 별도 CSRF 토큰 발급을 쓰지 않아 비활성화했다.
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    /*
     * Gateway는 외부 API/인증 endpoint만 제공한다. 그 외 직접 접근은 명시적으로 차단한다.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain fallbackSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize.anyRequest().denyAll())
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    /*
     * 로그아웃 성공 후 처리.
     *
     * Spring의 OIDC logout handler가 Keycloak end_session_endpoint로 보낼 URL을 만든다.
     * 인증 정보가 없으면 React 홈으로 돌려보내고, OIDC logout 실패는 성공 로그아웃과 구분되게 처리한다.
     */
    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler(
            ClientRegistrationRepository clientRegistrationRepository,
            @Value("${app.frontend-base-url}") String frontendBaseUrl
    ) {
        OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        logoutSuccessHandler.setPostLogoutRedirectUri(frontendBaseUrl);
        logoutSuccessHandler.setDefaultTargetUrl(frontendBaseUrl);
        return (request, response, authentication) -> {
            if (authentication == null) {
                response.sendRedirect(frontendBaseUrl);
                return;
            }

            try {
                logoutSuccessHandler.onLogoutSuccess(request, response, authentication);
            } catch (Exception e) {
                log.error("OIDC logout failed", e);
                if (!response.isCommitted()) {
                    response.sendRedirect(logoutFailureRedirectUrl(frontendBaseUrl));
                    return;
                }
                throw new ServletException("OIDC logout failed after response was committed", e);
            }
        };
    }

    /*
     * OAuth2 로그인 성공 후 처리.
     *
     * 일반 로그인 성공이면 SavedRequest가 있으면 원래 요청으로, 없으면 React 진입점으로 이동한다.
     * 마이페이지에서 비밀번호 변경을 시작한 경우에는 저장해 둔 /mypage 경로로 우선 복귀한다.
     */
    @Bean
    public AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler(
            @Value("${app.frontend-base-url}") String frontendBaseUrl
    ) {
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setRequestCache(new HttpSessionRequestCache());
        successHandler.setDefaultTargetUrl(frontendBaseUrl);
        successHandler.setAlwaysUseDefaultTargetUrl(true);

        return (request, response, authentication) -> {
            if (authentication != null && authentication.getName() != null && !authentication.getName().isBlank()) {
                request.getSession().setAttribute(
                        FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
                        authentication.getName()
                );
            }

            String passwordChangeTarget = (String) request.getSession()
                    .getAttribute(AuthController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE);

            if (passwordChangeTarget != null) {
                // UPDATE_PASSWORD 완료 후에는 일반 SavedRequest보다 비밀번호 변경을 시작한 React 화면으로 우선 복귀한다.
                request.getSession().removeAttribute(AuthController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE);
                response.sendRedirect(passwordChangeTarget);
                return;
            }

            successHandler.onAuthenticationSuccess(request, response, authentication);
        };
    }

    /*
     * OAuth2 로그인 실패 후 처리.
     *
     * Keycloak AIA 비밀번호 변경을 취소하거나 실패한 경우도 OAuth2 실패로 들어올 수 있다.
     * 이때는 에러 페이지 대신 React 마이페이지로 돌려보내 후속 안내를 맡긴다.
     */
    @Bean
    public AuthenticationFailureHandler oauth2AuthenticationFailureHandler(
            @Value("${app.frontend-base-url}") String frontendBaseUrl
    ) {
        SimpleUrlAuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler(frontendBaseUrl);
        return (request, response, exception) -> {
            String passwordChangeTarget = (String) request.getSession()
                    .getAttribute(AuthController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE);

            if (passwordChangeTarget != null) {
                // 사용자가 Required Action을 취소하거나 실패해도 React가 마이페이지에서 후속 안내를 처리할 수 있게 한다.
                request.getSession().removeAttribute(AuthController.PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE);
                response.sendRedirect(passwordChangeTarget);
                return;
            }

            failureHandler.onAuthenticationFailure(request, response, exception);
        };
    }

    /*
     * OAuth2 authorization request를 만들 때 한 번 가로채는 resolver.
     *
     * /oauth2/authorization/keycloak?kc_action=UPDATE_PASSWORD 로 들어온 요청에
     * kc_action을 Keycloak authorization request의 additional parameter로 실어 보낸다.
     */
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

    /*
     * React dev server와 Gateway가 포트가 달라 생기는 CORS를 허용한다.
     *
     * credentials 포함 요청이 필요하므로 allowedOrigins에는 "*"가 아니라 명시적인 origin만 넣는다.
     */
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

    // Keycloak 비밀번호 변경 AIA 요청일 때만 kc_action 파라미터를 OAuth2 요청에 추가한다.
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

    // 쉼표로 받은 설정값을 origin 목록으로 정규화한다. path는 CORS origin이 아니므로 제거한다.
    private List<String> corsAllowedOrigins(String configuredOrigins) {
        if (configuredOrigins == null || configuredOrigins.isBlank()) {
            return List.of(DEFAULT_FRONTEND_ORIGIN);
        }

        List<String> allowedOrigins = Arrays.stream(configuredOrigins.split(","))
                .map(String::trim)
                .filter(origin -> !origin.isBlank())
                .map(this::toOrigin)
                .filter(Objects::nonNull)
                .distinct()
                .toList();

        if (allowedOrigins.isEmpty()) {
            return List.of(DEFAULT_FRONTEND_ORIGIN);
        }
        return allowedOrigins;
    }

    // "https://domain/path" 형태가 들어와도 CORS에는 "https://domain"만 사용한다.
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

    private String logoutFailureRedirectUrl(String frontendBaseUrl) {
        String separator = frontendBaseUrl.contains("?") ? "&" : "?";
        return frontendBaseUrl + separator + "logout_error=1";
    }
}
