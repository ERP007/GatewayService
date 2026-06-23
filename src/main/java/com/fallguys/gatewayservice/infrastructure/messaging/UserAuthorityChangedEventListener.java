package com.fallguys.gatewayservice.infrastructure.messaging;

import com.fallguys.gatewayservice.domain.GatewaySessionInvalidationService;
import com.rabbitmq.client.Channel;
import java.io.IOException;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessagePostProcessor;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

@Slf4j
@Component
@RequiredArgsConstructor
public class UserAuthorityChangedEventListener {

    public static final String RETRY_COUNT_HEADER = "x-gateway-retry-count";
    public static final String LAST_ERROR_HEADER = "x-gateway-last-error";
    public static final String FAILED_AT_HEADER = "x-gateway-failed-at";
    public static final String DEAD_LETTERED_AT_HEADER = "x-gateway-dead-lettered-at";

    private final GatewaySessionInvalidationService sessionInvalidationService;
    private final SessionInvalidationMessagingProperties properties;
    private final RabbitTemplate rabbitTemplate;
    private final ObjectMapper objectMapper;

    @RabbitListener(
            queues = "${app.session-invalidation.messaging.queue}",
            autoStartup = "${app.session-invalidation.messaging.enabled:true}",
            containerFactory = "sessionInvalidationRabbitListenerContainerFactory"
    )
    public void handle(UserAuthorityChangedEvent event, Message message, Channel channel) throws IOException {
        long deliveryTag = message.getMessageProperties().getDeliveryTag();
        logPayloadIfEnabled(event);
        String keycloakSub = event == null ? null : event.keycloakSub();
        if (keycloakSub == null || keycloakSub.isBlank()) {
            log.warn(
                    "Ignored user authority changed event without keycloakSub. eventId={}, correlationId={}",
                    event == null ? null : event.eventId(),
                    event == null ? null : event.correlationId()
            );
            channel.basicAck(deliveryTag, false);
            return;
        }

        try {
            int expiredCount = sessionInvalidationService.expireByPrincipalName(keycloakSub);
            channel.basicAck(deliveryTag, false);
            log.info(
                    "Expired Gateway sessions after user authority change. eventId={}, correlationId={}, principalName={}, expiredCount={}",
                    event.eventId(),
                    event.correlationId(),
                    keycloakSub,
                    expiredCount
            );
        } catch (RuntimeException ex) {
            retryOrDeadLetter(event, message, channel, deliveryTag, ex);
        }
    }

    private void logPayloadIfEnabled(UserAuthorityChangedEvent event) {
        if (!properties.payloadLoggingEnabled()) {
            return;
        }
        if (event == null) {
            log.info("Received null user authority changed event payload.");
            return;
        }
        log.info(
                "Received user authority changed event payload. eventId={}, eventType={}, producer={}, correlationId={}, payloadJson={}",
                event.eventId(),
                event.eventType(),
                event.producer(),
                event.correlationId(),
                toJson(event.payload())
        );
    }

    private String toJson(UserAuthorityChangedEvent.Payload payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception ex) {
            log.warn("Failed to serialize user authority changed event payload for logging.", ex);
            return String.valueOf(payload);
        }
    }

    private void retryOrDeadLetter(
            UserAuthorityChangedEvent event,
            Message message,
            Channel channel,
            long deliveryTag,
            RuntimeException failure
    ) throws IOException {
        int retryCount = retryCount(message);
        if (retryCount >= properties.maxRetryAttempts()) {
            deadLetter(event, message, channel, deliveryTag, retryCount, failure);
            return;
        }

        int nextRetryCount = retryCount + 1;
        try {
            rabbitTemplate.convertAndSend(
                    properties.retryExchange(),
                    properties.retryRoutingKey(),
                    event,
                    retryMessage(message, nextRetryCount, failure)
            );
            channel.basicAck(deliveryTag, false);
            log.warn(
                    "Scheduled Gateway session invalidation retry. eventId={}, correlationId={}, retryCount={}, maxRetryAttempts={}",
                    event.eventId(),
                    event.correlationId(),
                    nextRetryCount,
                    properties.maxRetryAttempts(),
                    failure
            );
        } catch (RuntimeException publishFailure) {
            log.error(
                    "Failed to publish Gateway session invalidation retry message. eventId={}, correlationId={}",
                    event.eventId(),
                    event.correlationId(),
                    publishFailure
            );
            channel.basicNack(deliveryTag, false, true);
        }
    }

    private void deadLetter(
            UserAuthorityChangedEvent event,
            Message message,
            Channel channel,
            long deliveryTag,
            int retryCount,
            RuntimeException failure
    ) throws IOException {
        try {
            rabbitTemplate.convertAndSend(
                    properties.deadLetterExchange(),
                    properties.deadLetterRoutingKey(),
                    event,
                    deadLetterMessage(message, retryCount, failure)
            );
            channel.basicAck(deliveryTag, false);
            log.error(
                    "Moved Gateway session invalidation event to DLQ. eventId={}, correlationId={}, retryCount={}",
                    event.eventId(),
                    event.correlationId(),
                    retryCount,
                    failure
            );
        } catch (RuntimeException publishFailure) {
            log.error(
                    "Failed to publish Gateway session invalidation DLQ message. eventId={}, correlationId={}",
                    event.eventId(),
                    event.correlationId(),
                    publishFailure
            );
            channel.basicNack(deliveryTag, false, true);
        }
    }

    private MessagePostProcessor retryMessage(Message original, int retryCount, RuntimeException failure) {
        return message -> {
            copyHeaders(original, message);
            message.getMessageProperties().setHeader(RETRY_COUNT_HEADER, retryCount);
            message.getMessageProperties().setHeader(LAST_ERROR_HEADER, truncate(failure.getMessage()));
            message.getMessageProperties().setHeader(FAILED_AT_HEADER, java.time.Instant.now().toString());
            return message;
        };
    }

    private MessagePostProcessor deadLetterMessage(Message original, int retryCount, RuntimeException failure) {
        return message -> {
            copyHeaders(original, message);
            message.getMessageProperties().setHeader(RETRY_COUNT_HEADER, retryCount);
            message.getMessageProperties().setHeader(LAST_ERROR_HEADER, truncate(failure.getMessage()));
            message.getMessageProperties().setHeader(DEAD_LETTERED_AT_HEADER, java.time.Instant.now().toString());
            return message;
        };
    }

    private void copyHeaders(Message original, Message target) {
        for (Map.Entry<String, Object> entry : original.getMessageProperties().getHeaders().entrySet()) {
            target.getMessageProperties().setHeader(entry.getKey(), entry.getValue());
        }
    }

    private int retryCount(Message message) {
        Object value = message.getMessageProperties().getHeader(RETRY_COUNT_HEADER);
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text) {
            try {
                return Integer.parseInt(text);
            } catch (NumberFormatException ignored) {
                return 0;
            }
        }
        return 0;
    }

    private String truncate(String message) {
        if (message == null) {
            return null;
        }
        return message.length() <= 500 ? message : message.substring(0, 500);
    }
}
