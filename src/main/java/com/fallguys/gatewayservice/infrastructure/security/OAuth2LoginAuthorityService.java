package com.fallguys.gatewayservice.infrastructure.security;

import com.nimbusds.jwt.JWTParser;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class OAuth2LoginAuthorityService {

    private static final Logger log = LoggerFactory.getLogger(OAuth2LoginAuthorityService.class);

    private static final String USER_ROLE_CLAIM = "user_role";
    private static final String DEFAULT_NAME_ATTRIBUTE = "sub";

    private final OAuth2AuthorizedClientRepository authorizedClientRepository;

    public Authentication enhance(
            Authentication authentication,
            HttpServletRequest request
    ) {
        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Authentication)) {
            return authentication;
        }

        OAuth2AuthorizedClient authorizedClient = authorizedClientRepository.loadAuthorizedClient(
                oauth2Authentication.getAuthorizedClientRegistrationId(),
                oauth2Authentication,
                request
        );
        if (authorizedClient == null || authorizedClient.getAccessToken() == null) {
            return authentication;
        }

        String userRole = userRole(authorizedClient.getAccessToken().getTokenValue());
        if (userRole == null || userRole.isBlank()) {
            return authentication;
        }

        List<GrantedAuthority> authorities = authorities(oauth2Authentication.getAuthorities(), userRole);
        OAuth2User principal = principal(oauth2Authentication.getPrincipal(), authorities);
        OAuth2AuthenticationToken enhancedAuthentication = new OAuth2AuthenticationToken(
                principal,
                authorities,
                oauth2Authentication.getAuthorizedClientRegistrationId()
        );
        enhancedAuthentication.setDetails(oauth2Authentication.getDetails());
        return enhancedAuthentication;
    }

    private String userRole(String accessTokenValue) {
        try {
            Object value = JWTParser.parse(accessTokenValue).getJWTClaimsSet().getClaim(USER_ROLE_CLAIM);
            return value == null ? null : value.toString();
        } catch (ParseException e) {
            log.warn("Failed to parse OAuth2 access token while mapping user_role authority.", e);
            return null;
        }
    }

    private List<GrantedAuthority> authorities(
            Collection<? extends GrantedAuthority> existingAuthorities,
            String userRole
    ) {
        LinkedHashSet<String> authorityNames = new LinkedHashSet<>();
        existingAuthorities.stream()
                .map(GrantedAuthority::getAuthority)
                .forEach(authorityNames::add);
        authorityNames.add(userRole);
        authorityNames.add("ROLE_" + userRole);

        return authorityNames.stream()
                .map(SimpleGrantedAuthority::new)
                .map(GrantedAuthority.class::cast)
                .toList();
    }

    private OAuth2User principal(
            OAuth2User principal,
            Collection<? extends GrantedAuthority> authorities
    ) {
        if (principal instanceof OidcUser oidcUser) {
            return new DefaultOidcUser(
                    authorities,
                    oidcUser.getIdToken(),
                    oidcUser.getUserInfo(),
                    principalNameAttribute(principal.getAttributes())
            );
        }

        return new DefaultOAuth2User(
                authorities,
                principal.getAttributes(),
                principalNameAttribute(principal.getAttributes())
        );
    }

    private String principalNameAttribute(Map<String, Object> attributes) {
        if (attributes.containsKey(DEFAULT_NAME_ATTRIBUTE)) {
            return DEFAULT_NAME_ATTRIBUTE;
        }
        return attributes.keySet().stream()
                .findFirst()
                .orElse(DEFAULT_NAME_ATTRIBUTE);
    }
}
