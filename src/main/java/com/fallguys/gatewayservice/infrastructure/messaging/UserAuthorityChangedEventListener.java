package com.fallguys.gatewayservice.infrastructure.messaging;

import com.fallguys.gatewayservice.domain.GatewaySessionInvalidationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class UserAuthorityChangedEventListener {

    private final GatewaySessionInvalidationService sessionInvalidationService;

    @RabbitListener(
            queues = "${app.session-invalidation.messaging.queue}",
            autoStartup = "${app.session-invalidation.messaging.enabled:true}"
    )
    public void handle(UserAuthorityChangedEvent event) {
        String keycloakSub = event == null ? null : event.keycloakSub();
        if (keycloakSub == null || keycloakSub.isBlank()) {
            log.warn("Ignored user authority changed event without keycloakSub. event={}", event);
            return;
        }

        int expiredCount = sessionInvalidationService.expireByPrincipalName(keycloakSub);
        log.info(
                "Expired Gateway sessions after user authority change. eventId={}, correlationId={}, principalName={}, expiredCount={}",
                event.eventId(),
                event.correlationId(),
                keycloakSub,
                expiredCount
        );
    }
}
