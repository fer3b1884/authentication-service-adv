package by.shved.authenticationserviceadv.service.token;

import by.shved.authenticationserviceadv.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenRevocationService {
    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void revokeAllUserTokens(Long userId) {
        int revokedCount = refreshTokenRepository.revokeAllActiveTokensByUserId(userId);
        log.warn("All active refresh tokens revoked: userId={}, count={}", userId, revokedCount);
    }
}
