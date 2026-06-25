package com.fallguys.gatewayservice.controller.dto;

import java.time.Instant;

public record DemoSwitchAccountResponse(
        String employeeNo,
        String username,
        Instant accessTokenExpiresAt
) {
}
