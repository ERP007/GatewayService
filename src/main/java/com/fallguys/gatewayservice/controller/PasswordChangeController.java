package com.fallguys.gatewayservice.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PasswordChangeController {

    public static final String PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE = "PASSWORD_CHANGE_TARGET";

    private final String frontendBaseUrl;

    public PasswordChangeController(@Value("${app.frontend-base-url}") String frontendBaseUrl) {
        this.frontendBaseUrl = frontendBaseUrl;
    }

    @GetMapping("/auth/password-change")
    public String passwordChange(HttpServletRequest request) {
        request.getSession().setAttribute(PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE, frontendBaseUrl + "/mypage");
        return "redirect:/oauth2/authorization/keycloak?kc_action=UPDATE_PASSWORD";
    }
}
