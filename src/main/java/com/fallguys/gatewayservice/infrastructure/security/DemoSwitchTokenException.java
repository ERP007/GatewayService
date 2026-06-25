package com.fallguys.gatewayservice.infrastructure.security;

public class DemoSwitchTokenException extends RuntimeException {

    public DemoSwitchTokenException(String message) {
        super(message);
    }

    public DemoSwitchTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
