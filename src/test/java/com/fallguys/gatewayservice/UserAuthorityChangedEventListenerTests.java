package com.fallguys.gatewayservice;

import com.fallguys.gatewayservice.domain.GatewaySessionInvalidationService;
import com.fallguys.gatewayservice.infrastructure.messaging.SessionInvalidationMessagingProperties;
import com.fallguys.gatewayservice.infrastructure.messaging.UserAuthorityChangedEvent;
import com.fallguys.gatewayservice.infrastructure.messaging.UserAuthorityChangedEventListener;
import com.rabbitmq.client.Channel;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageBuilder;
import org.springframework.amqp.core.MessagePostProcessor;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.junit.jupiter.api.extension.ExtendWith;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@ExtendWith(OutputCaptureExtension.class)
class UserAuthorityChangedEventListenerTests {

    @Test
    void handleExpiresSessionsByKeycloakSubject() throws IOException {
        GatewaySessionInvalidationService sessionInvalidationService =
                mock(GatewaySessionInvalidationService.class);
        RabbitTemplate rabbitTemplate = mock(RabbitTemplate.class);
        Channel channel = mock(Channel.class);
        UserAuthorityChangedEventListener listener =
                new UserAuthorityChangedEventListener(
                        sessionInvalidationService,
                        properties(),
                        rabbitTemplate,
                        new ObjectMapper()
                );
        UserAuthorityChangedEvent event = event("keycloak-sub-001");

        listener.handle(event, message(1), channel);

        verify(sessionInvalidationService).expireByPrincipalName("keycloak-sub-001");
        verify(channel).basicAck(1, false);
        verifyNoInteractions(rabbitTemplate);
    }

    @Test
    void handleIgnoresEventWithoutKeycloakSubject() throws IOException {
        GatewaySessionInvalidationService sessionInvalidationService =
                mock(GatewaySessionInvalidationService.class);
        RabbitTemplate rabbitTemplate = mock(RabbitTemplate.class);
        Channel channel = mock(Channel.class);
        UserAuthorityChangedEventListener listener =
                new UserAuthorityChangedEventListener(
                        sessionInvalidationService,
                        properties(),
                        rabbitTemplate,
                        new ObjectMapper()
                );

        listener.handle(new UserAuthorityChangedEvent(
                "event-001",
                "user.authority.changed",
                1,
                "user-service",
                "2026-06-23T13:00:05Z",
                "USER-keycloak-sub-001",
                new UserAuthorityChangedEvent.Payload(" ", "ADMIN002", "USER_PROFILE_UPDATED")
        ), message(2), channel);

        verifyNoInteractions(sessionInvalidationService);
        verify(channel).basicAck(2, false);
        verifyNoInteractions(rabbitTemplate);
    }

    @Test
    void handleSchedulesRetryWhenRedisSessionInvalidationFails() throws Exception {
        GatewaySessionInvalidationService sessionInvalidationService =
                mock(GatewaySessionInvalidationService.class);
        RabbitTemplate rabbitTemplate = mock(RabbitTemplate.class);
        Channel channel = mock(Channel.class);
        UserAuthorityChangedEvent event = event("keycloak-sub-001");
        UserAuthorityChangedEventListener listener =
                new UserAuthorityChangedEventListener(
                        sessionInvalidationService,
                        properties(),
                        rabbitTemplate,
                        new ObjectMapper()
                );
        doThrow(new IllegalStateException("redis timeout"))
                .when(sessionInvalidationService)
                .expireByPrincipalName("keycloak-sub-001");
        Message originalMessage = message(3);
        originalMessage.getMessageProperties()
                .setHeader("__TypeId__", "com.fallguys.userservice.shared.infrastructure.messaging.UserAuthorityChangedMessage");
        originalMessage.getMessageProperties().setHeader("x-death", "rabbitmq-managed");
        originalMessage.getMessageProperties().setHeader("content-type", "application/json");
        originalMessage.getMessageProperties().setHeader("x-gateway-redrive-count", 2);

        listener.handle(event, originalMessage, channel);

        ArgumentCaptor<MessagePostProcessor> postProcessorCaptor =
                ArgumentCaptor.forClass(MessagePostProcessor.class);
        verify(rabbitTemplate).convertAndSend(
                eq("gateway.session-invalidation.retry"),
                eq("user.authority.changed.gateway.retry"),
                eq(event),
                postProcessorCaptor.capture()
        );
        Message retryMessage = message(10);
        retryMessage.getMessageProperties()
                .setHeader("__TypeId__", "com.fallguys.gatewayservice.infrastructure.messaging.UserAuthorityChangedEvent");
        postProcessorCaptor.getValue().postProcessMessage(retryMessage);
        assertThat((Integer) retryMessage.getMessageProperties()
                .getHeader(UserAuthorityChangedEventListener.RETRY_COUNT_HEADER)).isEqualTo(1);
        assertThat((String) retryMessage.getMessageProperties()
                .getHeader(UserAuthorityChangedEventListener.LAST_ERROR_HEADER)).isEqualTo("redis timeout");
        assertThat((String) retryMessage.getMessageProperties().getHeader("__TypeId__"))
                .isEqualTo("com.fallguys.gatewayservice.infrastructure.messaging.UserAuthorityChangedEvent");
        assertThat((Object) retryMessage.getMessageProperties().getHeader("x-death")).isNull();
        assertThat((Object) retryMessage.getMessageProperties().getHeader("content-type")).isNull();
        assertThat((Integer) retryMessage.getMessageProperties().getHeader("x-gateway-redrive-count"))
                .isEqualTo(2);
        verify(channel).basicAck(3, false);
    }

    @Test
    void handleMovesEventToDlqWhenRetryAttemptsAreExhausted() throws Exception {
        GatewaySessionInvalidationService sessionInvalidationService =
                mock(GatewaySessionInvalidationService.class);
        RabbitTemplate rabbitTemplate = mock(RabbitTemplate.class);
        Channel channel = mock(Channel.class);
        UserAuthorityChangedEvent event = event("keycloak-sub-001");
        UserAuthorityChangedEventListener listener =
                new UserAuthorityChangedEventListener(
                        sessionInvalidationService,
                        properties(),
                        rabbitTemplate,
                        new ObjectMapper()
                );
        Message message = message(4);
        message.getMessageProperties()
                .setHeader(UserAuthorityChangedEventListener.RETRY_COUNT_HEADER, 5);
        doThrow(new IllegalStateException("redis timeout"))
                .when(sessionInvalidationService)
                .expireByPrincipalName("keycloak-sub-001");

        listener.handle(event, message, channel);

        ArgumentCaptor<MessagePostProcessor> postProcessorCaptor =
                ArgumentCaptor.forClass(MessagePostProcessor.class);
        verify(rabbitTemplate).convertAndSend(
                eq("gateway.session-invalidation.dlx"),
                eq("user.authority.changed.gateway.dlq"),
                eq(event),
                postProcessorCaptor.capture()
        );
        Message deadLetterMessage = postProcessorCaptor.getValue().postProcessMessage(message(11));
        assertThat((Integer) deadLetterMessage.getMessageProperties()
                .getHeader(UserAuthorityChangedEventListener.RETRY_COUNT_HEADER)).isEqualTo(5);
        assertThat((String) deadLetterMessage.getMessageProperties()
                .getHeader(UserAuthorityChangedEventListener.LAST_ERROR_HEADER)).isEqualTo("redis timeout");
        verify(channel).basicAck(4, false);
    }

    @Test
    void handleRequeuesOriginalMessageWhenRetryPublishFails() throws Exception {
        GatewaySessionInvalidationService sessionInvalidationService =
                mock(GatewaySessionInvalidationService.class);
        RabbitTemplate rabbitTemplate = mock(RabbitTemplate.class);
        Channel channel = mock(Channel.class);
        UserAuthorityChangedEvent event = event("keycloak-sub-001");
        UserAuthorityChangedEventListener listener =
                new UserAuthorityChangedEventListener(
                        sessionInvalidationService,
                        properties(),
                        rabbitTemplate,
                        new ObjectMapper()
                );
        doThrow(new IllegalStateException("redis timeout"))
                .when(sessionInvalidationService)
                .expireByPrincipalName("keycloak-sub-001");
        doThrow(new IllegalStateException("rabbitmq publish failed"))
                .when(rabbitTemplate)
                .convertAndSend(
                        eq("gateway.session-invalidation.retry"),
                        eq("user.authority.changed.gateway.retry"),
                        eq(event),
                        org.mockito.ArgumentMatchers.any(MessagePostProcessor.class)
                );

        listener.handle(event, message(5), channel);

        verify(channel).basicNack(5, false, true);
        verifyNoMoreInteractions(channel);
    }

    @Test
    void handleLogsPayloadAsJsonWhenPayloadLoggingEnabled(CapturedOutput output) throws IOException {
        GatewaySessionInvalidationService sessionInvalidationService =
                mock(GatewaySessionInvalidationService.class);
        RabbitTemplate rabbitTemplate = mock(RabbitTemplate.class);
        Channel channel = mock(Channel.class);
        UserAuthorityChangedEventListener listener =
                new UserAuthorityChangedEventListener(
                        sessionInvalidationService,
                        properties(true),
                        rabbitTemplate,
                        new ObjectMapper()
                );

        listener.handle(event("keycloak-sub-001"), message(6), channel);

        assertThat(output.getOut())
                .contains("payloadJson={\"keycloakSub\":\"keycloak-sub-001\",\"employeeNo\":\"ADMIN002\",\"reason\":\"USER_PROFILE_UPDATED\"}");
    }

    @Test
    void eventBodyMatchesRoutingSpecification() throws Exception {
        String json = """
                {
                  "eventId": "7c3e0b76-44d0-4f53-9e65-200000000013",
                  "eventType": "user.authority.changed",
                  "eventVersion": 1,
                  "producer": "user-service",
                  "occurredAt": "2026-06-23T13:00:05Z",
                  "correlationId": "USER-4997ac1b-eb49-48fc-858c-a009f30b0533",
                  "payload": {
                    "keycloakSub": "4997ac1b-eb49-48fc-858c-a009f30b0533",
                    "employeeNo": "ADMIN002",
                    "reason": "USER_PROFILE_UPDATED"
                  }
                }
                """;

        UserAuthorityChangedEvent event = new ObjectMapper()
                .readValue(json, UserAuthorityChangedEvent.class);

        assertThat(event.eventType()).isEqualTo("user.authority.changed");
        assertThat(event.keycloakSub()).isEqualTo("4997ac1b-eb49-48fc-858c-a009f30b0533");
        assertThat(event.payload().employeeNo()).isEqualTo("ADMIN002");
    }

    private UserAuthorityChangedEvent event(String keycloakSub) {
        return new UserAuthorityChangedEvent(
                "event-001",
                "user.authority.changed",
                1,
                "user-service",
                "2026-06-23T13:00:05Z",
                "USER-" + keycloakSub,
                new UserAuthorityChangedEvent.Payload(
                        keycloakSub,
                        "ADMIN002",
                        "USER_PROFILE_UPDATED"
                )
        );
    }

    private Message message(long deliveryTag) {
        Message message = MessageBuilder.withBody(new byte[0]).build();
        message.getMessageProperties().setDeliveryTag(deliveryTag);
        return message;
    }

    private SessionInvalidationMessagingProperties properties() {
        return properties(false);
    }

    private SessionInvalidationMessagingProperties properties(boolean payloadLoggingEnabled) {
        return new SessionInvalidationMessagingProperties(
                true,
                payloadLoggingEnabled,
                "erp.events",
                "gateway.user-session-invalidation.q",
                "user.authority.changed.gateway",
                "gateway.session-invalidation.retry",
                "gateway.user-session-invalidation.retry.q",
                "user.authority.changed.gateway.retry",
                30_000,
                5,
                "gateway.session-invalidation.dlx",
                "gateway.user-session-invalidation.dlq",
                "user.authority.changed.gateway.dlq",
                new SessionInvalidationMessagingProperties.DlqRedrive(true, 60_000, 10, 3)
        );
    }
}
