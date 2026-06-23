package com.fallguys.gatewayservice.infrastructure.messaging;

import org.junit.jupiter.api.Test;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageBuilder;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.support.converter.MessageConverter;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class UserAuthorityChangedRabbitConversionTests {

    @Test
    void convertsUserServicePublishedMessageToGatewayEvent() {
        String userServiceJson = """
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
        Message message = MessageBuilder
                .withBody(userServiceJson.getBytes(StandardCharsets.UTF_8))
                .setContentType(MessageProperties.CONTENT_TYPE_JSON)
                .setHeader("__TypeId__", "com.fallguys.userservice.shared.infrastructure.messaging.UserAuthorityChangedMessage")
                .build();
        message.getMessageProperties().setInferredArgumentType(UserAuthorityChangedEvent.class);
        MessageConverter messageConverter = new RabbitMessagingConfig().rabbitMessageConverter();

        Object converted = messageConverter.fromMessage(message);

        assertThat(converted).isInstanceOf(UserAuthorityChangedEvent.class);
        UserAuthorityChangedEvent event = (UserAuthorityChangedEvent) converted;
        assertThat(event.eventType()).isEqualTo("user.authority.changed");
        assertThat(event.producer()).isEqualTo("user-service");
        assertThat(event.keycloakSub()).isEqualTo("4997ac1b-eb49-48fc-858c-a009f30b0533");
        assertThat(event.payload().employeeNo()).isEqualTo("ADMIN002");
        assertThat(event.payload().reason()).isEqualTo("USER_PROFILE_UPDATED");
    }
}
