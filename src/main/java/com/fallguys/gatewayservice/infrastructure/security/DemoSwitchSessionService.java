package com.fallguys.gatewayservice.infrastructure.security;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class DemoSwitchSessionService {

    private static final String KEYCLOAK_SUB_CLAIM = "sub";
    private static final String USER_ROLE_CLAIM = "user_role";

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    public String replaceSession(
            DemoSwitchTokenResponse tokenResponse,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId(
                tokenResponse.clientRegistrationId()
        );
        if (clientRegistration == null) {
            throw new DemoSwitchTokenException("Keycloak client registration is not configured.");
        }

        Map<String, Object> accessTokenClaims = jwtClaims(tokenResponse.accessTokenValue(), "access_token");
        String principalName = requiredClaim(accessTokenClaims, KEYCLOAK_SUB_CLAIM);
        OAuth2AccessToken accessToken = accessToken(tokenResponse);
        OAuth2RefreshToken refreshToken = refreshToken(tokenResponse);
        OAuth2AuthenticationToken authentication = authentication(
                clientRegistration,
                tokenResponse,
                accessTokenClaims
        );
        OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                clientRegistration,
                principalName,
                accessToken,
                refreshToken
        );

        rotateSessionIdIfPresent(request);
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);

        request.getSession(true).setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                securityContext
        );
        request.getSession().setAttribute(
                FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
                principalName
        );
        authorizedClientRepository.saveAuthorizedClient(authorizedClient, authentication, request, response);

        return principalName;
    }

    private OAuth2AccessToken accessToken(DemoSwitchTokenResponse tokenResponse) {
        return new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                tokenResponse.accessTokenValue(),
                tokenResponse.issuedAt(),
                tokenResponse.accessTokenExpiresAt(),
                tokenResponse.scopes()
        );
    }

    private OAuth2RefreshToken refreshToken(DemoSwitchTokenResponse tokenResponse) {
        if (tokenResponse.refreshTokenValue() == null || tokenResponse.refreshTokenValue().isBlank()) {
            return null;
        }
        return new OAuth2RefreshToken(tokenResponse.refreshTokenValue(), tokenResponse.issuedAt());
    }

    private OAuth2AuthenticationToken authentication(
            ClientRegistration clientRegistration,
            DemoSwitchTokenResponse tokenResponse,
            Map<String, Object> accessTokenClaims
    ) {
        Collection<GrantedAuthority> authorities = authorities(tokenResponse, accessTokenClaims);
        OAuth2User principal = principal(clientRegistration, tokenResponse, accessTokenClaims, authorities);
        return new OAuth2AuthenticationToken(
                principal,
                authorities,
                clientRegistration.getRegistrationId()
        );
    }

    private OAuth2User principal(
            ClientRegistration clientRegistration,
            DemoSwitchTokenResponse tokenResponse,
            Map<String, Object> accessTokenClaims,
            Collection<GrantedAuthority> authorities
    ) {
        String userNameAttributeName = userNameAttributeName(clientRegistration);
        if (tokenResponse.idTokenValue() == null || tokenResponse.idTokenValue().isBlank()) {
            return new DefaultOAuth2User(authorities, accessTokenClaims, userNameAttributeName);
        }

        Map<String, Object> idTokenClaims = jwtClaims(tokenResponse.idTokenValue(), "id_token");
        OidcIdToken idToken = new OidcIdToken(
                tokenResponse.idTokenValue(),
                instantClaim(idTokenClaims, "iat", tokenResponse.issuedAt()),
                instantClaim(idTokenClaims, "exp", tokenResponse.accessTokenExpiresAt()),
                idTokenClaims
        );
        return new DefaultOidcUser(authorities, idToken, userNameAttributeName);
    }

    private Collection<GrantedAuthority> authorities(
            DemoSwitchTokenResponse tokenResponse,
            Map<String, Object> accessTokenClaims
    ) {
        Map<String, Object> attributes = new LinkedHashMap<>(accessTokenClaims);
        List<GrantedAuthority> authorities = new ArrayList<>();
        if (tokenResponse.idTokenValue() == null || tokenResponse.idTokenValue().isBlank()) {
            authorities.add(new OAuth2UserAuthority(attributes));
        } else {
            OidcIdToken idToken = new OidcIdToken(
                    tokenResponse.idTokenValue(),
                    tokenResponse.issuedAt(),
                    tokenResponse.accessTokenExpiresAt(),
                    jwtClaims(tokenResponse.idTokenValue(), "id_token")
            );
            authorities.add(new OidcUserAuthority(idToken));
        }

        for (String scope : tokenResponse.scopes()) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
        }

        String userRole = stringClaim(accessTokenClaims, USER_ROLE_CLAIM);
        if (userRole != null && !userRole.isBlank()) {
            authorities.add(new SimpleGrantedAuthority(userRole));
            authorities.add(new SimpleGrantedAuthority("ROLE_" + userRole));
        }

        return authorities;
    }

    private String userNameAttributeName(ClientRegistration clientRegistration) {
        String configuredNameAttribute = clientRegistration.getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();
        if (configuredNameAttribute == null || configuredNameAttribute.isBlank()) {
            return KEYCLOAK_SUB_CLAIM;
        }
        return configuredNameAttribute;
    }

    private Map<String, Object> jwtClaims(String tokenValue, String tokenName) {
        try {
            JWTClaimsSet claimsSet = JWTParser.parse(tokenValue).getJWTClaimsSet();
            return new LinkedHashMap<>(claimsSet.getClaims());
        } catch (ParseException e) {
            throw new DemoSwitchTokenException("Failed to parse demo switch " + tokenName + ".", e);
        }
    }

    private String requiredClaim(Map<String, Object> claims, String claimName) {
        String value = stringClaim(claims, claimName);
        if (value == null || value.isBlank()) {
            throw new DemoSwitchTokenException("Demo switch token is missing " + claimName + " claim.");
        }
        return value;
    }

    private String stringClaim(Map<String, Object> claims, String claimName) {
        Object value = claims.get(claimName);
        return value == null ? null : value.toString();
    }

    private Instant instantClaim(Map<String, Object> claims, String claimName, Instant fallback) {
        Object value = claims.get(claimName);
        if (value instanceof Date date) {
            return date.toInstant();
        }
        if (value instanceof Instant instant) {
            return instant;
        }
        if (value instanceof Number number) {
            return Instant.ofEpochSecond(number.longValue());
        }
        return fallback;
    }

    private void rotateSessionIdIfPresent(HttpServletRequest request) {
        if (request.getSession(false) != null) {
            request.changeSessionId();
        }
    }
}
