package by.shved.authenticationserviceadv.service.impl;

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
import by.shved.authenticationserviceadv.service.jwt.JwtService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserCredentialsRepository userCredentialsRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @Value("${security.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;
    @Value("${security.jwt.access-token-expiration}")
    private long accessTokenExpiration;

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
                credentials.getRole()
        );
        String refreshToken = jwtService.generateRefreshToken(
                credentials.getUserId(),
                credentials.getRole(),
                tokenId
        );

        RefreshTokenEntity refreshTokenEntity = new RefreshTokenEntity();
        refreshTokenEntity.setUserId(credentials.getUserId());
        refreshTokenEntity.setTokenId(tokenId);
        refreshTokenEntity.setRevoked(false);
        refreshTokenEntity.setExpiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpiration / 1000));
        refreshTokenRepository.save(refreshTokenEntity);

        return new TokenResponse(
                accessToken,
                refreshToken,
                "Bearer",
                accessTokenExpiration / 1000
        );
    }

    @Override
    @Transactional
    public TokenResponse refresh(RefreshTokenRequest request) {
        String oldToken = request.refreshToken();
        if (!jwtService.isTokenValid(oldToken, TokenType.REFRESH)) {
            throw new InvalidTokenException("Invalid refresh token");
        }
        UUID oldTokenId = jwtService.extractTokenId(oldToken);
        Long userId = jwtService.extractUserId(oldToken);
        RefreshTokenEntity storedToken = refreshTokenRepository
                .findByTokenId(oldTokenId)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));
        if (storedToken.isRevoked()
                || !storedToken.getUserId().equals(userId)
                || !storedToken.getExpiresAt().isAfter(LocalDateTime.now())
        ) {
            throw new InvalidTokenException("Invalid refresh token");
        }
        UserCredentialsEntity credentials = userCredentialsRepository
                .findByUserId(userId)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        UUID newTokenId = UUID.randomUUID();
        String accessToken = jwtService.generateAccessToken(
                credentials.getUserId(),
                credentials.getRole()
        );
        String refreshToken = jwtService.generateRefreshToken(
                credentials.getUserId(),
                credentials.getRole(),
                newTokenId
        );
        storedToken.setRevoked(true);
        refreshTokenRepository.save(storedToken);

        RefreshTokenEntity newStoredToken = new RefreshTokenEntity();
        newStoredToken.setUserId(credentials.getUserId());
        newStoredToken.setTokenId(newTokenId);
        newStoredToken.setRevoked(false);
        newStoredToken.setExpiresAt(LocalDateTime.now().plusSeconds(refreshTokenExpiration / 1000));
        refreshTokenRepository.save(newStoredToken);

        return new TokenResponse(
                accessToken,
                refreshToken,
                "Bearer",
                accessTokenExpiration / 1000
        );
    }

    @Override
    public TokenValidationResponse validateToken(String token) {
        if (!jwtService.isTokenValid(token, TokenType.ACCESS)) {
            return new TokenValidationResponse(false, null, null);
        }
        Long userId = jwtService.extractUserId(token);
        String role = jwtService.extractRole(token).name();
        return new TokenValidationResponse(true, userId, role);
    }
}
