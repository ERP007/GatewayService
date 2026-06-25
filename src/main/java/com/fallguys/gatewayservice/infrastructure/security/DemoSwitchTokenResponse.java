package com.fallguys.gatewayservice.infrastructure.security;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public record DemoSwitchTokenResponse(
        String clientRegistrationId,
        String accessTokenValue,
        String refreshTokenValue,
        String idTokenValue,
        String tokenType,
        Instant issuedAt,
        Instant accessTokenExpiresAt,
        Set<String> scopes
) {

    static DemoSwitchTokenResponse from(
            String clientRegistrationId,
            Map<String, Object> response,
            Instant issuedAt,
            Set<String> fallbackScopes
    ) {
        if (response == null) {
            throw new DemoSwitchTokenException("Keycloak token response body is empty.");
        }

        String accessTokenValue = requiredString(response, "access_token");
        long expiresIn = requiredPositiveLong(response, "expires_in");

        return new DemoSwitchTokenResponse(
                clientRegistrationId,
                accessTokenValue,
                stringValue(response, "refresh_token"),
                stringValue(response, "id_token"),
                stringValue(response, "token_type", "Bearer"),
                issuedAt,
                issuedAt.plusSeconds(expiresIn),
                scopes(response, fallbackScopes)
        );
    }

    private static String requiredString(Map<String, Object> response, String key) {
        String value = stringValue(response, key);
        if (value == null || value.isBlank()) {
            throw new DemoSwitchTokenException("Keycloak token response is missing " + key + ".");
        }
        return value;
    }

    private static String stringValue(Map<String, Object> response, String key) {
        Object value = response.get(key);
        return value == null ? null : value.toString();
    }

    private static String stringValue(Map<String, Object> response, String key, String defaultValue) {
        String value = stringValue(response, key);
        return value == null || value.isBlank() ? defaultValue : value;
    }

    private static long requiredPositiveLong(Map<String, Object> response, String key) {
        Object value = response.get(key);
        if (value instanceof Number number && number.longValue() > 0) {
            return number.longValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                long parsed = Long.parseLong(text);
                if (parsed > 0) {
                    return parsed;
                }
            } catch (NumberFormatException ignored) {
                // handled below
            }
        }
        throw new DemoSwitchTokenException("Keycloak token response is missing " + key + ".");
    }

    private static Set<String> scopes(Map<String, Object> response, Set<String> fallbackScopes) {
        String scope = stringValue(response, "scope");
        if (scope == null || scope.isBlank()) {
            return Set.copyOf(fallbackScopes);
        }
        return new LinkedHashSet<>(Arrays.stream(scope.split(" "))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .toList());
    }
}
