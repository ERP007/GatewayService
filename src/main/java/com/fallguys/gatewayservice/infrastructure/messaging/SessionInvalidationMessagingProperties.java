package com.fallguys.gatewayservice.infrastructure.messaging;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "app.session-invalidation.messaging")
public record SessionInvalidationMessagingProperties(
        boolean enabled,
        @NotBlank String exchange,
        @NotBlank String queue,
        @NotBlank String routingKey
) {
}
