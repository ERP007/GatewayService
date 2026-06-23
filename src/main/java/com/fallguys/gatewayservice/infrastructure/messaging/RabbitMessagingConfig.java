package com.fallguys.gatewayservice.infrastructure.messaging;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.DirectExchange;
import org.springframework.amqp.core.AcknowledgeMode;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.config.SimpleRabbitListenerContainerFactory;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
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
    DirectExchange gatewaySessionInvalidationRetryExchange(SessionInvalidationMessagingProperties properties) {
        return new DirectExchange(properties.retryExchange(), true, false);
    }

    @Bean
    Queue gatewaySessionInvalidationRetryQueue(SessionInvalidationMessagingProperties properties) {
        return QueueBuilder.durable(properties.retryQueue())
                .ttl(Math.toIntExact(properties.retryDelayMs()))
                .deadLetterExchange(properties.exchange())
                .deadLetterRoutingKey(properties.routingKey())
                .build();
    }

    @Bean
    Binding gatewaySessionInvalidationRetryBinding(
            DirectExchange gatewaySessionInvalidationRetryExchange,
            Queue gatewaySessionInvalidationRetryQueue,
            SessionInvalidationMessagingProperties properties
    ) {
        return BindingBuilder.bind(gatewaySessionInvalidationRetryQueue)
                .to(gatewaySessionInvalidationRetryExchange)
                .with(properties.retryRoutingKey());
    }

    @Bean
    DirectExchange gatewaySessionInvalidationDeadLetterExchange(SessionInvalidationMessagingProperties properties) {
        return new DirectExchange(properties.deadLetterExchange(), true, false);
    }

    @Bean
    Queue gatewaySessionInvalidationDeadLetterQueue(SessionInvalidationMessagingProperties properties) {
        return QueueBuilder.durable(properties.deadLetterQueue()).build();
    }

    @Bean
    Binding gatewaySessionInvalidationDeadLetterBinding(
            DirectExchange gatewaySessionInvalidationDeadLetterExchange,
            Queue gatewaySessionInvalidationDeadLetterQueue,
            SessionInvalidationMessagingProperties properties
    ) {
        return BindingBuilder.bind(gatewaySessionInvalidationDeadLetterQueue)
                .to(gatewaySessionInvalidationDeadLetterExchange)
                .with(properties.deadLetterRoutingKey());
    }

    @Bean
    MessageConverter rabbitMessageConverter() {
        return new JacksonJsonMessageConverter();
    }

    @Bean
    SimpleRabbitListenerContainerFactory sessionInvalidationRabbitListenerContainerFactory(
            ConnectionFactory connectionFactory,
            MessageConverter rabbitMessageConverter
    ) {
        SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
        factory.setConnectionFactory(connectionFactory);
        factory.setMessageConverter(rabbitMessageConverter);
        factory.setAcknowledgeMode(AcknowledgeMode.MANUAL);
        factory.setDefaultRequeueRejected(false);
        return factory;
    }
}
