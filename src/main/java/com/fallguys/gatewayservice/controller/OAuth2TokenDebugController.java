package com.fallguys.gatewayservice.controller;

import com.nimbusds.jwt.JWTParser;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/debug")
@ConditionalOnProperty(prefix = "app.debug", name = "oauth2-token-enabled", havingValue = "true")
public class OAuth2TokenDebugController {

    @GetMapping("/oauth2-token")
    public ResponseEntity<Map<String, Object>> token(
            @RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient client
    ) {
        OAuth2AccessToken accessToken = client.getAccessToken();
        OAuth2RefreshToken refreshToken = client.getRefreshToken();
        Map<String, Object> accessTokenClaims = decodeJwtClaims(accessToken.getTokenValue());

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("clientRegistrationId", client.getClientRegistration().getRegistrationId());
        response.put("principalName", client.getPrincipalName());
        response.put("accessToken", accessToken(accessToken, accessTokenClaims));
        response.put("refreshToken", refreshToken(refreshToken));
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header("Pragma", "no-cache")
                .body(response);
    }

    private Map<String, Object> accessToken(
            OAuth2AccessToken accessToken,
            Map<String, Object> claims
    ) {
        Map<String, Object> token = new LinkedHashMap<>();
        token.put("tokenValue", accessToken.getTokenValue());
        token.put("tokenType", accessToken.getTokenType().getValue());
        token.put("issuedAt", accessToken.getIssuedAt());
        token.put("expiresAt", accessToken.getExpiresAt());
        token.put("scopes", accessToken.getScopes());
        token.put("userRole", claims.get("user_role"));
        token.put("claims", claims);
        return token;
    }

    private Map<String, Object> refreshToken(OAuth2RefreshToken refreshToken) {
        if (refreshToken == null) {
            return null;
        }

        Map<String, Object> token = new LinkedHashMap<>();
        token.put("tokenValue", refreshToken.getTokenValue());
        token.put("issuedAt", refreshToken.getIssuedAt());
        token.put("expiresAt", refreshToken.getExpiresAt());
        return token;
    }

    private Map<String, Object> decodeJwtClaims(String tokenValue) {
        try {
            return new LinkedHashMap<>(JWTParser.parse(tokenValue).getJWTClaimsSet().getClaims());
        } catch (Exception e) {
            return Map.of("decodeError", e.getMessage());
        }
    }
}
