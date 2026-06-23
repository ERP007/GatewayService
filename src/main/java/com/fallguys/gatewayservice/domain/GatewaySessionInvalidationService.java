package com.fallguys.gatewayservice.domain;

import lombok.RequiredArgsConstructor;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class GatewaySessionInvalidationService {

    private final FindByIndexNameSessionRepository<? extends Session> sessionRepository;

    /**
     * Keycloak subject를 principalName으로 사용하는 Gateway 세션을 모두 만료한다.
     *
     * 흐름:
     * 1) Spring Session Redis indexed repository에서 principalName 기준 세션 목록을 조회한다.
     * 2) 조회된 세션 ID를 Redis session repository에서 삭제한다.
     *
     * 트랜잭션: Redis 세션 저장소 단건 삭제들의 조합이며 DB 트랜잭션 경계는 없다.
     *
     * 예외: Redis 연결 실패 또는 세션 저장소 오류가 발생하면 호출자에게 전파되어 메시지 재처리 정책을 따른다.
     */
    public int expireByPrincipalName(String principalName) {
        Map<String, ? extends Session> sessions =
                sessionRepository.findByPrincipalName(principalName);

        for (String sessionId : sessions.keySet()) {
            sessionRepository.deleteById(sessionId);
        }

        return sessions.size();
    }
}
