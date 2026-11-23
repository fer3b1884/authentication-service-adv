package by.shved.authenticationserviceadv.scheduler;

import by.shved.authenticationserviceadv.service.token.RefreshTokenCleanupService;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RefreshTokenCleanupScheduler {
    private final RefreshTokenCleanupService cleanupService;

    @Scheduled(cron = "0 0 0 * * *")
    public void cleanupExpiredTokens() {
        cleanupService.deleteExpiredTokens();
    }
}
