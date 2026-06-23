package com.fallguys.gatewayservice.infrastructure.messaging;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(
        prefix = "app.session-invalidation.messaging.dlq-redrive",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
public class UserAuthorityChangedDlqRedriveScheduler {

    private final UserAuthorityChangedDlqRedriveService redriveService;
    private final SessionInvalidationMessagingProperties properties;

    @Scheduled(fixedDelayString = "${app.session-invalidation.messaging.dlq-redrive.fixed-delay-ms:60000}")
    public void redrive() {
        try {
            int redrivenCount = redriveService.redrive(properties.dlqRedrive().batchSize());
            if (redrivenCount > 0) {
                log.info("Redrove Gateway session invalidation DLQ messages. count={}", redrivenCount);
            }
        } catch (RuntimeException ex) {
            log.warn("Failed to redrive Gateway session invalidation DLQ messages. It will retry later.", ex);
        }
    }
}
