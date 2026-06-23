package com.fallguys.gatewayservice.infrastructure.messaging;

import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.GetResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class UserAuthorityChangedDlqRedriveService {

    static final String REDRIVEN_AT_HEADER = "x-gateway-redriven-at";
    static final String REDRIVE_COUNT_HEADER = "x-gateway-redrive-count";

    private final RabbitTemplate rabbitTemplate;
    private final RedisConnectionFactory redisConnectionFactory;
    private final SessionInvalidationMessagingProperties properties;

    public int redrive(int batchSize) {
        if (!isRedisAvailable()) {
            log.warn("Skipped Gateway session invalidation DLQ redrive because Redis is unavailable.");
            return 0;
        }

        int redrivenCount = 0;
        for (int i = 0; i < batchSize; i++) {
            if (!redriveOne()) {
                break;
            }
            redrivenCount++;
        }
        return redrivenCount;
    }

    private boolean redriveOne() {
        Boolean redriven = rabbitTemplate.execute(channel -> {
            GetResponse response = channel.basicGet(properties.deadLetterQueue(), false);
            if (response == null) {
                return false;
            }

            long deliveryTag = response.getEnvelope().getDeliveryTag();
            try {
                channel.basicPublish(
                        properties.exchange(),
                        properties.routingKey(),
                        false,
                        redriveProperties(response.getProps()),
                        response.getBody()
                );
                channel.basicAck(deliveryTag, false);
                return true;
            } catch (IOException | RuntimeException ex) {
                channel.basicNack(deliveryTag, false, true);
                throw ex;
            }
        });
        return Boolean.TRUE.equals(redriven);
    }

    private AMQP.BasicProperties redriveProperties(AMQP.BasicProperties source) {
        Map<String, Object> headers = new LinkedHashMap<>();
        if (source.getHeaders() != null) {
            headers.putAll(source.getHeaders());
        }
        headers.put(UserAuthorityChangedEventListener.RETRY_COUNT_HEADER, 0);
        headers.put(REDRIVEN_AT_HEADER, Instant.now().toString());
        headers.put(REDRIVE_COUNT_HEADER, redriveCount(headers) + 1);

        return source.builder()
                .headers(headers)
                .build();
    }

    private int redriveCount(Map<String, Object> headers) {
        Object value = headers.get(REDRIVE_COUNT_HEADER);
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

    private boolean isRedisAvailable() {
        try (RedisConnection connection = redisConnectionFactory.getConnection()) {
            return "PONG".equalsIgnoreCase(connection.ping());
        } catch (RuntimeException ex) {
            return false;
        }
    }
}
