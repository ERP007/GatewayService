package com.fallguys.gatewayservice.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/gateway")
public class HealthController {

    @GetMapping("/health")
    public String health() {
        return "api-gateway ok";
    }
}
