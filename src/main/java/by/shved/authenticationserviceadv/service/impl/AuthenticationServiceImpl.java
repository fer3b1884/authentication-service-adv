package by.shved.authenticationserviceadv.service.impl;

import by.shved.authenticationserviceadv.config.property.JwtProperties;
import by.shved.authenticationserviceadv.dto.credentials.LoginRequest;
import by.shved.authenticationserviceadv.dto.token.RefreshTokenRequest;
import by.shved.authenticationserviceadv.dto.token.TokenResponse;
import by.shved.authenticationserviceadv.dto.token.TokenValidationResponse;
import by.shved.authenticationserviceadv.entity.RefreshTokenEntity;
import by.shved.authenticationserviceadv.entity.TokenType;
import by.shved.authenticationserviceadv.entity.UserCredentialsEntity;
import by.shved.authenticationserviceadv.exception.InvalidTokenException;
import by.shved.authenticationserviceadv.repository.RefreshTokenRepository;
import by.shved.authenticationserviceadv.repository.UserCredentialsRepository;
import by.shved.authenticationserviceadv.service.AuthenticationService;
import by.shved.authenticationserviceadv.service.jwt.JwtPayload;
import by.shved.authenticationserviceadv.service.jwt.JwtService;
import by.shved.authenticationserviceadv.service.token.RefreshTokenRevocationService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserCredentialsRepository userCredentialsRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenRevocationService refreshTokenRevocationService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    @Override
    @Transactional
    public TokenResponse login(LoginRequest request) {
        UserCredentialsEntity credentials = userCredentialsRepository
                .findByLogin(request.login())
                .orElseThrow(() -> new BadCredentialsException("Invalid login or password"));
        if (!passwordEncoder.matches(request.password(), credentials.getPasswordHash())) {
            throw new BadCredentialsException("Invalid login or password");
        }

        UUID tokenId = UUID.randomUUID();
        String accessToken = jwtService.generateAccessToken(
                credentials.getUserId(),
                credentials.getRole(),
                UUID.randomUUID()
        );
        String refreshToken = jwtService.generateRefreshToken(
                credentials.getUserId(),
                credentials.getRole(),
                tokenId
        );

        refreshTokenRepository.save(createRefreshToken(
                credentials.getUserId(),
                tokenId
        ));
        log.info("User authenticated successfully: userId={}, role={}",
                credentials.getUserId(), credentials.getRole());
        return new TokenResponse(
                accessToken,
                refreshToken,
                "Bearer",
                jwtProperties.accessTokenExpiration().toSeconds()
        );
    }

    @Override
    @Transactional
    public TokenResponse refresh(RefreshTokenRequest request) {
        JwtPayload payload = jwtService
                .parseAndValidate(request.refreshToken(), TokenType.REFRESH)
                .orElseThrow(() -> new InvalidTokenException("Invalid or expired refresh token"));
        UUID oldTokenId = payload.tokenId();
        Long userId = payload.userId();
        LocalDateTime now = LocalDateTime.now();
        int revokedCount = refreshTokenRepository.revokeIfValid(
                oldTokenId,
                userId,
                now
        );
        if (revokedCount != 1) {
            refreshTokenRepository.findByTokenId(oldTokenId)
                    .filter(RefreshTokenEntity::isRevoked)
                    .ifPresent(token -> refreshTokenRevocationService.revokeAllUserTokens(userId));
            throw new InvalidTokenException("Invalid or expired refresh token");
        }
        UserCredentialsEntity credentials = userCredentialsRepository
                .findByUserId(userId)
                .orElseThrow(() -> new InvalidTokenException("Invalid or expired refresh token"));

        UUID newTokenId = UUID.randomUUID();
        String accessToken = jwtService.generateAccessToken(
                credentials.getUserId(),
                credentials.getRole(),
                UUID.randomUUID()
        );
        String refreshToken = jwtService.generateRefreshToken(
                credentials.getUserId(),
                credentials.getRole(),
                newTokenId
        );

        refreshTokenRepository.save(createRefreshToken(
                credentials.getUserId(),
                newTokenId
        ));
        log.info("Tokens refreshed successfully: userId={}", userId);
        return new TokenResponse(
                accessToken,
                refreshToken,
                "Bearer",
                jwtProperties.accessTokenExpiration().toSeconds()
        );
    }

    @Override
    public TokenValidationResponse validateToken(String token) {
        JwtPayload payload = jwtService
                .parseAndValidate(token, TokenType.ACCESS)
                .orElse(null);

        if (payload == null) {
            log.debug("Access token validation failed");
            return new TokenValidationResponse(false, null, null);
        }
        Long userId = payload.userId();
        String role = payload.role().name();
        log.info("Access token validated successfully: userId={}, role={}", userId, role);
        return new TokenValidationResponse(true, userId, role);
    }

    private RefreshTokenEntity createRefreshToken(Long userId, UUID tokenId) {
        RefreshTokenEntity refreshToken = new RefreshTokenEntity();
        refreshToken.setUserId(userId);
        refreshToken.setTokenId(tokenId);
        refreshToken.setRevoked(false);
        refreshToken.setExpiresAt(LocalDateTime.now().plus(jwtProperties.refreshTokenExpiration()));
        return refreshToken;
    }
}
