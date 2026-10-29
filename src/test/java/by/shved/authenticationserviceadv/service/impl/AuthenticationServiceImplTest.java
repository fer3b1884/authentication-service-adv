package by.shved.authenticationserviceadv.service.impl;

import by.shved.authenticationserviceadv.dto.credentials.LoginRequest;
import by.shved.authenticationserviceadv.dto.token.RefreshTokenRequest;
import by.shved.authenticationserviceadv.dto.token.TokenResponse;
import by.shved.authenticationserviceadv.entity.RefreshTokenEntity;
import by.shved.authenticationserviceadv.entity.TokenType;
import by.shved.authenticationserviceadv.entity.UserCredentialsEntity;
import by.shved.authenticationserviceadv.entity.UserRole;
import by.shved.authenticationserviceadv.exception.InvalidTokenException;
import by.shved.authenticationserviceadv.repository.RefreshTokenRepository;
import by.shved.authenticationserviceadv.repository.UserCredentialsRepository;
import by.shved.authenticationserviceadv.service.jwt.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceImplTest {
    @Mock
    private UserCredentialsRepository userCredentialsRepository;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private JwtService jwtService;
    @InjectMocks
    private AuthenticationServiceImpl authenticationService;

    private UserCredentialsEntity credentials;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authenticationService, "accessTokenExpiration", 900000L);
        ReflectionTestUtils.setField(authenticationService, "refreshTokenExpiration", 604800000L);

        credentials = new UserCredentialsEntity();
        credentials.setUserId(1L);
        credentials.setLogin("test-user");
        credentials.setPasswordHash("encoded-password");
        credentials.setRole(UserRole.ROLE_USER);
    }

    @Test
    void login_validCredentials_returnsTokens() {
        LoginRequest loginRequest = new LoginRequest("test-user", "password");

        when(userCredentialsRepository.findByLogin("test-user")).thenReturn(Optional.of(credentials));
        when(passwordEncoder.matches("password", "encoded-password")).thenReturn(true);
        when(jwtService.generateAccessToken(1L, UserRole.ROLE_USER)).thenReturn("access-token");
        when(jwtService.generateRefreshToken(eq(1L), eq(UserRole.ROLE_USER), any(UUID.class))).thenReturn("refresh-token");
        TokenResponse response = authenticationService.login(loginRequest);

        assertEquals("access-token", response.accessToken());
        assertEquals("refresh-token", response.refreshToken());
        assertEquals("Bearer", response.tokenType());
        assertEquals(900L, response.expiresIn());
        verify(refreshTokenRepository).save(any(RefreshTokenEntity.class));
    }

    @Test
    void login_unknownLogin_throwsException() {
        LoginRequest loginRequest = new LoginRequest("unknown", "password");

        when(userCredentialsRepository.findByLogin("unknown")).thenReturn(Optional.empty());

        assertThrows(BadCredentialsException.class, () -> authenticationService.login(loginRequest));
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void login_wrongPassword_throwsException() {
        LoginRequest loginRequest = new LoginRequest("test-user", "wrong-password");

        when(userCredentialsRepository.findByLogin("test-user")).thenReturn(Optional.of(credentials));
        when(passwordEncoder.matches("wrong-password", "encoded-password")).thenReturn(false);

        assertThrows(BadCredentialsException.class, () -> authenticationService.login(loginRequest));
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void refresh_invalidToken_throwsException() {
        when(jwtService.isTokenValid("invalid-token", TokenType.REFRESH)).thenReturn(false);

        assertThrows(InvalidTokenException.class, () -> authenticationService.refresh(new RefreshTokenRequest("invalid-token")));
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void refresh_validToken_rotatesRefreshToken() {
        String oldToken = "old-refresh-token";
        UUID oldTokenId = UUID.randomUUID();
        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest(oldToken);

        RefreshTokenEntity storedToken = new RefreshTokenEntity();
        storedToken.setUserId(1L);
        storedToken.setTokenId(oldTokenId);
        storedToken.setRevoked(false);
        storedToken.setExpiresAt(LocalDateTime.now().plusDays(1));

        when(jwtService.isTokenValid(oldToken, TokenType.REFRESH)).thenReturn(true);
        when(jwtService.extractTokenId(oldToken)).thenReturn(oldTokenId);
        when(jwtService.extractUserId(oldToken)).thenReturn(1L);
        when(refreshTokenRepository.findByTokenId(oldTokenId)).thenReturn(Optional.of(storedToken));
        when(userCredentialsRepository.findByUserId(1L)).thenReturn(Optional.of(credentials));
        when(jwtService.generateAccessToken(1L, UserRole.ROLE_USER)).thenReturn("new-access-token");
        when(jwtService.generateRefreshToken(eq(1L), eq(UserRole.ROLE_USER), any(UUID.class))).thenReturn("new-refresh-token");

        TokenResponse response = authenticationService.refresh(refreshTokenRequest);

        assertEquals("new-access-token", response.accessToken());
        assertEquals("new-refresh-token", response.refreshToken());
        assertTrue(storedToken.isRevoked());
        verify(refreshTokenRepository, times(2)).save(any(RefreshTokenEntity.class));
    }
}