package com.fallguys.gatewayservice.infrastructure.messaging;

import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Envelope;
import com.rabbitmq.client.GetResponse;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.amqp.rabbit.core.ChannelCallback;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class UserAuthorityChangedDlqRedriveServiceTests {

    @Test
    void redriveRepublishesDlqMessageWhenRedisIsAvailable() throws Exception {
        RabbitTemplate rabbitTemplate = mock(RabbitTemplate.class);
        RedisConnectionFactory redisConnectionFactory = mock(RedisConnectionFactory.class);
        RedisConnection redisConnection = mock(RedisConnection.class);
        Channel channel = mock(Channel.class);
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        AMQP.BasicProperties sourceProperties = new AMQP.BasicProperties.Builder()
                .contentType("application/json")
                .headers(new HashMap<>(Map.of(
                        UserAuthorityChangedEventListener.RETRY_COUNT_HEADER, 5,
                        UserAuthorityChangedDlqRedriveService.REDRIVE_COUNT_HEADER, 2
                )))
                .build();
        GetResponse response = new GetResponse(
                new Envelope(101, false, "gateway.session-invalidation.dlx", "user.authority.changed.gateway.dlq"),
                sourceProperties,
                body,
                0
        );
        when(redisConnectionFactory.getConnection()).thenReturn(redisConnection);
        when(redisConnection.ping()).thenReturn("PONG");
        when(channel.basicGet("gateway.user-session-invalidation.dlq", false))
                .thenReturn(response)
                .thenReturn(null);
        when(rabbitTemplate.execute(any())).thenAnswer(invocation -> {
            ChannelCallback<Boolean> callback = invocation.getArgument(0);
            return callback.doInRabbit(channel);
        });
        UserAuthorityChangedDlqRedriveService service =
                new UserAuthorityChangedDlqRedriveService(rabbitTemplate, redisConnectionFactory, properties());

        int redrivenCount = service.redrive(10);

        assertThat(redrivenCount).isEqualTo(1);
        ArgumentCaptor<AMQP.BasicProperties> propertiesCaptor =
                ArgumentCaptor.forClass(AMQP.BasicProperties.class);
        verify(channel).basicPublish(
                eq("erp.events"),
                eq("user.authority.changed.gateway"),
                eq(false),
                propertiesCaptor.capture(),
                eq(body)
        );
        assertThat(propertiesCaptor.getValue().getHeaders())
                .containsEntry(UserAuthorityChangedEventListener.RETRY_COUNT_HEADER, 0)
                .containsEntry(UserAuthorityChangedDlqRedriveService.REDRIVE_COUNT_HEADER, 3)
                .containsKey(UserAuthorityChangedDlqRedriveService.REDRIVEN_AT_HEADER);
        verify(channel).basicAck(101, false);
    }

    @Test
    void redriveSkipsDlqWhenRedisIsUnavailable() {
        RabbitTemplate rabbitTemplate = mock(RabbitTemplate.class);
        RedisConnectionFactory redisConnectionFactory = mock(RedisConnectionFactory.class);
        when(redisConnectionFactory.getConnection()).thenThrow(new IllegalStateException("redis down"));
        UserAuthorityChangedDlqRedriveService service =
                new UserAuthorityChangedDlqRedriveService(rabbitTemplate, redisConnectionFactory, properties());

        int redrivenCount = service.redrive(10);

        assertThat(redrivenCount).isZero();
        verifyNoInteractions(rabbitTemplate);
    }

    private SessionInvalidationMessagingProperties properties() {
        return new SessionInvalidationMessagingProperties(
                true,
                false,
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
                new SessionInvalidationMessagingProperties.DlqRedrive(true, 60_000, 10)
        );
    }
}
