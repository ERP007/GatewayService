package com.fallguys.gatewayservice.controller;

import com.fallguys.gatewayservice.controller.dto.DemoSwitchAccountRequest;
import com.fallguys.gatewayservice.controller.dto.DemoSwitchAccountResponse;
import com.fallguys.gatewayservice.infrastructure.security.DemoSwitchProperties;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
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

    @PostMapping("/switch-account")
    public ResponseEntity<DemoSwitchAccountResponse> switchAccount(
            @Valid @RequestBody DemoSwitchAccountRequest request,
            Authentication authentication
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

        return ResponseEntity.ok(new DemoSwitchAccountResponse(employeeNo, account.username()));
    }

    private boolean canSwitchAccount(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

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
