package by.shved.authenticationserviceadv.service.jwt;

import by.shved.authenticationserviceadv.entity.TokenType;
import by.shved.authenticationserviceadv.entity.UserRole;

import java.time.Instant;
import java.util.UUID;

public record JwtPayload(
        Long userId,
        UserRole role,
        TokenType tokenType,
        UUID tokenId,
        Instant expiresAt
) {
}
