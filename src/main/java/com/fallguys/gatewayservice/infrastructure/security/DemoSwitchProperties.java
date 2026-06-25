package com.fallguys.gatewayservice.infrastructure.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

@ConfigurationProperties(prefix = "app.demo-switch")
public record DemoSwitchProperties(
        boolean enabled,
        Map<String, Account> accounts
) {

    public DemoSwitchProperties {
        accounts = normalizeAccounts(accounts);
        if (enabled && accounts.isEmpty()) {
            throw new IllegalStateException("app.demo-switch.accounts must not be empty when demo switch is enabled.");
        }
        if (enabled) {
            accounts.forEach(DemoSwitchProperties::validateConfiguredAccount);
        }
    }

    public Optional<Account> findAccount(String employeeNo) {
        if (employeeNo == null || employeeNo.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(accounts.get(normalizeEmployeeNo(employeeNo)));
    }

    private static Map<String, Account> normalizeAccounts(Map<String, Account> source) {
        if (source == null || source.isEmpty()) {
            return Map.of();
        }

        Map<String, Account> normalized = new LinkedHashMap<>();
        source.forEach((employeeNo, account) -> {
            String normalizedEmployeeNo = normalizeEmployeeNo(employeeNo);
            normalized.put(normalizedEmployeeNo, account == null ? new Account("", "") : account);
        });
        return Collections.unmodifiableMap(normalized);
    }

    private static String normalizeEmployeeNo(String employeeNo) {
        if (employeeNo == null || employeeNo.isBlank()) {
            throw new IllegalArgumentException("Demo switch employeeNo must not be blank.");
        }
        return employeeNo.trim().toUpperCase(Locale.ROOT);
    }

    private static void validateConfiguredAccount(String employeeNo, Account account) {
        if (account.username().isBlank()) {
            throw new IllegalStateException(
                    "app.demo-switch.accounts." + employeeNo + ".username must not be blank when demo switch is enabled."
            );
        }
        if (account.password().isBlank()) {
            throw new IllegalStateException(
                    "app.demo-switch.accounts." + employeeNo + ".password must not be blank when demo switch is enabled."
            );
        }
    }

    public record Account(
            String username,
            String password
    ) {

        public Account {
            username = username == null ? "" : username.trim();
            password = password == null ? "" : password;
        }
    }
}
