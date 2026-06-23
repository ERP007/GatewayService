package com.fallguys.gatewayservice.infrastructure.messaging;

public record UserAuthorityChangedEvent(
        String eventId,
        String eventType,
        Integer eventVersion,
        String producer,
        String occurredAt,
        String correlationId,
        Payload payload
) {

    public String keycloakSub() {
        return payload == null ? null : payload.keycloakSub();
    }

    public record Payload(
            String keycloakSub,
            String employeeNo,
            String reason
    ) {
    }
}
