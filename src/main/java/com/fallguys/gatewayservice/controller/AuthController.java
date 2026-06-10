package com.fallguys.gatewayservice.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/api/auth")
public class AuthController {

    public static final String PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE = "PASSWORD_CHANGE_TARGET";

    private final String frontendBaseUrl;

    public AuthController(@Value("${app.frontend-base-url}") String frontendBaseUrl) {
        this.frontendBaseUrl = frontendBaseUrl;
    }

    @GetMapping("/password-change")
    public String passwordChange(HttpServletRequest request) {
        // Keycloak Required Action 완료/취소 후 OAuth2 callback에서 다시 보낼 React 화면을 세션에 보관한다.
        request.getSession().setAttribute(PASSWORD_CHANGE_TARGET_SESSION_ATTRIBUTE, frontendBaseUrl + "/mypage");

        // Spring Security authorization endpoint를 거치면서 SecurityConfig가 kc_action을 Keycloak 요청에 포함시킨다.
        return "redirect:/oauth2/authorization/keycloak?kc_action=UPDATE_PASSWORD";
    }
}
