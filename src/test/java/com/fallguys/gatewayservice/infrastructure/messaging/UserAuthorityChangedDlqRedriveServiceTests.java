package com.fallguys.gatewayservice.infrastructure.messaging;

import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Envelope;
import com.rabbitmq.client.GetResponse;
import com.rabbitmq.client.ReturnCallback;
import com.rabbitmq.client.ReturnListener;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.amqp.rabbit.core.ChannelCallback;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.rabbit.support.RabbitExceptionTranslator;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
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
        ReturnListener returnListener = mock(ReturnListener.class);
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
        when(channel.addReturnListener(any(ReturnCallback.class))).thenReturn(returnListener);
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
                eq(true),
                propertiesCaptor.capture(),
                eq(body)
        );
        verify(channel).confirmSelect();
        verify(channel).waitForConfirmsOrDie(5_000);
        assertThat(propertiesCaptor.getValue().getHeaders())
                .containsEntry(UserAuthorityChangedEventListener.RETRY_COUNT_HEADER, 0)
                .containsEntry(UserAuthorityChangedDlqRedriveService.REDRIVE_COUNT_HEADER, 3)
                .containsKey(UserAuthorityChangedDlqRedriveService.REDRIVEN_AT_HEADER);
        verify(channel).basicAck(101, false);
        verify(channel).removeReturnListener(returnListener);
    }

    @Test
    void redriveRequeuesDlqMessageWhenPublishConfirmFails() throws Exception {
        RabbitTemplate rabbitTemplate = mock(RabbitTemplate.class);
        RedisConnectionFactory redisConnectionFactory = mock(RedisConnectionFactory.class);
        RedisConnection redisConnection = mock(RedisConnection.class);
        Channel channel = mock(Channel.class);
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        AMQP.BasicProperties sourceProperties = new AMQP.BasicProperties.Builder()
                .contentType("application/json")
                .build();
        GetResponse response = new GetResponse(
                new Envelope(101, false, "gateway.session-invalidation.dlx", "user.authority.changed.gateway.dlq"),
                sourceProperties,
                body,
                0
        );
        when(redisConnectionFactory.getConnection()).thenReturn(redisConnection);
        when(redisConnection.ping()).thenReturn("PONG");
        when(channel.basicGet("gateway.user-session-invalidation.dlq", false)).thenReturn(response);
        doThrow(new IOException("publish not confirmed"))
                .when(channel)
                .waitForConfirmsOrDie(5_000);
        when(rabbitTemplate.execute(any())).thenAnswer(invocation -> {
            ChannelCallback<Boolean> callback = invocation.getArgument(0);
            try {
                return callback.doInRabbit(channel);
            } catch (Exception ex) {
                throw RabbitExceptionTranslator.convertRabbitAccessException(ex);
            }
        });
        UserAuthorityChangedDlqRedriveService service =
                new UserAuthorityChangedDlqRedriveService(rabbitTemplate, redisConnectionFactory, properties());

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> service.redrive(10))
                .isInstanceOf(RuntimeException.class)
                .hasCauseInstanceOf(IOException.class);

        verify(channel).basicPublish(
                eq("erp.events"),
                eq("user.authority.changed.gateway"),
                eq(true),
                any(AMQP.BasicProperties.class),
                eq(body)
        );
        verify(channel).basicNack(101, false, true);
    }

    @Test
    void redriveLeavesMessageInDlqWhenMaxRedriveAttemptsReached() throws Exception {
        RabbitTemplate rabbitTemplate = mock(RabbitTemplate.class);
        RedisConnectionFactory redisConnectionFactory = mock(RedisConnectionFactory.class);
        RedisConnection redisConnection = mock(RedisConnection.class);
        Channel channel = mock(Channel.class);
        AMQP.BasicProperties sourceProperties = new AMQP.BasicProperties.Builder()
                .contentType("application/json")
                .headers(new HashMap<>(Map.of(
                        UserAuthorityChangedDlqRedriveService.REDRIVE_COUNT_HEADER, 3
                )))
                .build();
        GetResponse response = new GetResponse(
                new Envelope(101, false, "gateway.session-invalidation.dlx", "user.authority.changed.gateway.dlq"),
                sourceProperties,
                "{}".getBytes(StandardCharsets.UTF_8),
                0
        );
        when(redisConnectionFactory.getConnection()).thenReturn(redisConnection);
        when(redisConnection.ping()).thenReturn("PONG");
        when(channel.basicGet("gateway.user-session-invalidation.dlq", false)).thenReturn(response);
        when(rabbitTemplate.execute(any())).thenAnswer(invocation -> {
            ChannelCallback<Boolean> callback = invocation.getArgument(0);
            return callback.doInRabbit(channel);
        });
        UserAuthorityChangedDlqRedriveService service =
                new UserAuthorityChangedDlqRedriveService(rabbitTemplate, redisConnectionFactory, properties());

        int redrivenCount = service.redrive(10);

        assertThat(redrivenCount).isZero();
        verify(channel).basicNack(101, false, true);
        verify(channel, never()).confirmSelect();
        verify(channel, never()).basicAck(101, false);
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
                new SessionInvalidationMessagingProperties.DlqRedrive(true, 60_000, 10, 3)
        );
    }
}
