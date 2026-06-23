package com.fallguys.gatewayservice;

import com.fallguys.gatewayservice.domain.GatewaySessionInvalidationService;
import org.junit.jupiter.api.Test;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class GatewaySessionInvalidationServiceTests {

    @Test
    @SuppressWarnings("unchecked")
    void expireByPrincipalNameDeletesAllSessionsForPrincipal() {
        FindByIndexNameSessionRepository<Session> sessionRepository = mock(FindByIndexNameSessionRepository.class);
        Session firstSession = mock(Session.class);
        Session secondSession = mock(Session.class);
        when(sessionRepository.findByPrincipalName("keycloak-sub-001"))
                .thenReturn(Map.of(
                        "session-001", firstSession,
                        "session-002", secondSession
                ));
        GatewaySessionInvalidationService service = new GatewaySessionInvalidationService(sessionRepository);

        int expiredCount = service.expireByPrincipalName("keycloak-sub-001");

        assertThat(expiredCount).isEqualTo(2);
        verify(sessionRepository).deleteById("session-001");
        verify(sessionRepository).deleteById("session-002");
    }
}
