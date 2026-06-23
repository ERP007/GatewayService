package com.fallguys.gatewayservice.infrastructure.messaging;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "app.session-invalidation.messaging")
public record SessionInvalidationMessagingProperties(
        boolean enabled,
        boolean payloadLoggingEnabled,
        @NotBlank String exchange,
        @NotBlank String queue,
        @NotBlank String routingKey,
        @NotBlank String retryExchange,
        @NotBlank String retryQueue,
        @NotBlank String retryRoutingKey,
        @Positive long retryDelayMs,
        @Positive int maxRetryAttempts,
        @NotBlank String deadLetterExchange,
        @NotBlank String deadLetterQueue,
        @NotBlank String deadLetterRoutingKey,
        @NotNull @Valid DlqRedrive dlqRedrive
) {

    public record DlqRedrive(
            boolean enabled,
            @Positive long fixedDelayMs,
            @Positive int batchSize,
            @Positive int maxAttempts
    ) {
    }
}
