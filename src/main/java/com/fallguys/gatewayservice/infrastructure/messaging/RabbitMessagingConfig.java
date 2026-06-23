package com.fallguys.gatewayservice.infrastructure.messaging;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.support.converter.JacksonJsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(SessionInvalidationMessagingProperties.class)
public class RabbitMessagingConfig {

    @Bean
    TopicExchange userEventsExchange(SessionInvalidationMessagingProperties properties) {
        return new TopicExchange(properties.exchange(), true, false);
    }

    @Bean
    Queue gatewaySessionInvalidationQueue(SessionInvalidationMessagingProperties properties) {
        return QueueBuilder.durable(properties.queue()).build();
    }

    @Bean
    Binding gatewaySessionInvalidationBinding(
            TopicExchange userEventsExchange,
            Queue gatewaySessionInvalidationQueue,
            SessionInvalidationMessagingProperties properties
    ) {
        return BindingBuilder.bind(gatewaySessionInvalidationQueue)
                .to(userEventsExchange)
                .with(properties.routingKey());
    }

    @Bean
    MessageConverter rabbitMessageConverter() {
        return new JacksonJsonMessageConverter();
    }
}
