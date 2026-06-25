package com.fallguys.gatewayservice.controller.dto;

import jakarta.validation.constraints.NotBlank;

public record DemoSwitchAccountRequest(
        @NotBlank String employeeNo
) {
}
