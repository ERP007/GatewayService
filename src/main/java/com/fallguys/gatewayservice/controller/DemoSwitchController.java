package com.fallguys.gatewayservice.controller;

import com.fallguys.gatewayservice.controller.dto.DemoSwitchAccountRequest;
import com.fallguys.gatewayservice.controller.dto.DemoSwitchAccountResponse;
import com.fallguys.gatewayservice.infrastructure.security.DemoSwitchProperties;
import com.fallguys.gatewayservice.infrastructure.security.DemoSwitchSessionService;
import com.fallguys.gatewayservice.infrastructure.security.DemoSwitchTokenClient;
import com.fallguys.gatewayservice.infrastructure.security.DemoSwitchTokenException;
import com.fallguys.gatewayservice.infrastructure.security.DemoSwitchTokenResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/api/auth/demo")
public class DemoSwitchController {

    private static final Set<String> SWITCHER_EXACT_AUTHORITIES = Set.of("ADMIN", "ROLE_ADMIN");
    private static final Set<String> SWITCHER_AUTHORITY_PREFIXES = Set.of(
            "HQ_",
            "ROLE_HQ_",
            "BRANCH_",
            "ROLE_BRANCH_"
    );

    private final DemoSwitchProperties demoSwitchProperties;
    private final DemoSwitchTokenClient demoSwitchTokenClient;
    private final DemoSwitchSessionService demoSwitchSessionService;

    @PostMapping("/switch-account")
    public ResponseEntity<DemoSwitchAccountResponse> switchAccount(
            @Valid @RequestBody DemoSwitchAccountRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse
    ) {
        if (!demoSwitchProperties.enabled()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        if (!canSwitchAccount(authentication)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }

        String employeeNo = normalizeEmployeeNo(request.employeeNo());
        DemoSwitchProperties.Account account = demoSwitchProperties.findAccount(employeeNo)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        DemoSwitchTokenResponse tokenResponse = issueToken(account);
        log.info(
                "Demo switch idToken present={}",
                tokenResponse.idTokenValue() != null && !tokenResponse.idTokenValue().isBlank()
        );
        replaceSession(tokenResponse, httpRequest, httpResponse);

        return ResponseEntity.ok(new DemoSwitchAccountResponse(
                employeeNo,
                account.username(),
                tokenResponse.accessTokenExpiresAt()
        ));
    }

    private DemoSwitchTokenResponse issueToken(DemoSwitchProperties.Account account) {
        try {
            return demoSwitchTokenClient.issueToken(account);
        } catch (DemoSwitchTokenException e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Failed to issue demo account token.", e);
        }
    }

    private void replaceSession(
            DemoSwitchTokenResponse tokenResponse,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        try {
            demoSwitchSessionService.replaceSession(tokenResponse, request, response);
        } catch (DemoSwitchTokenException e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Failed to switch demo account session.", e);
        }
    }

    private boolean canSwitchAccount(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        log.info(
                "Demo switch authentication name={}, authorities={}",
                authentication.getName(),
                authentication.getAuthorities()
        );

        Set<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        return authorities.stream().anyMatch(this::isSwitcherAuthority);
    }

    private boolean isSwitcherAuthority(String authority) {
        return SWITCHER_EXACT_AUTHORITIES.contains(authority)
                || SWITCHER_AUTHORITY_PREFIXES.stream().anyMatch(authority::startsWith);
    }

    private String normalizeEmployeeNo(String employeeNo) {
        return employeeNo.trim().toUpperCase(Locale.ROOT);
    }
}
