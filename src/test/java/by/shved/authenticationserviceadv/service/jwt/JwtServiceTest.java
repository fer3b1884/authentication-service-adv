package by.shved.authenticationserviceadv.service.jwt;

import by.shved.authenticationserviceadv.entity.TokenType;
import by.shved.authenticationserviceadv.entity.UserRole;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {
    private static final long ACCESS_TOKEN_EXPIRATION = 900_000L;
    private static final long REFRESH_TOKEN_EXPIRATION = 604_800_000L;

    private JwtService jwtService;
    private String secret;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();

        secret = generateSecretKey();
        ReflectionTestUtils.setField(jwtService, "secret", secret);
        ReflectionTestUtils.setField(jwtService, "accessTokenExpiration", ACCESS_TOKEN_EXPIRATION);
        ReflectionTestUtils.setField(jwtService, "refreshTokenExpiration", REFRESH_TOKEN_EXPIRATION);
    }

    @Test
    void generateAccessToken_validData_tokenIsValid() {
        String token = jwtService.generateAccessToken(1L, UserRole.ROLE_USER);

        assertNotNull(token);
        assertFalse(token.isBlank());
        assertTrue(jwtService.isTokenValid(token, TokenType.ACCESS));
    }

    @Test
    void generateAccessToken_validData_containsCorrectClaims() {
        String token = jwtService.generateAccessToken(1L, UserRole.ROLE_USER);

        assertEquals(1L, jwtService.extractUserId(token));
        assertEquals(UserRole.ROLE_USER, jwtService.extractRole(token));
        assertEquals(TokenType.ACCESS, jwtService.extractTokenType(token));
    }

    @Test
    void generateRefreshToken_validData_tokenIsValid() {
        UUID tokenId = UUID.randomUUID();
        String token = jwtService.generateRefreshToken(1L, UserRole.ROLE_USER, tokenId);

        assertNotNull(token);
        assertTrue(jwtService.isTokenValid(token, TokenType.REFRESH));
        assertEquals(tokenId, jwtService.extractTokenId(token));
    }

    @Test
    void isTokenValid_accessTokenCheckedAsRefreshToken_returnsFalse() {
        String token = jwtService.generateAccessToken(1L, UserRole.ROLE_USER);

        assertFalse(jwtService.isTokenValid(token, TokenType.REFRESH));
    }

    @Test
    void isTokenValid_refreshTokenCheckedAsAccessToken_returnsFalse() {
        String token = jwtService.generateRefreshToken(1L, UserRole.ROLE_USER, UUID.randomUUID());

        assertFalse(jwtService.isTokenValid(token, TokenType.ACCESS));
    }

    @Test
    void isTokenValid_invalidToken_returnsFalse() {
        assertFalse(jwtService.isTokenValid("invalid-token", TokenType.ACCESS));
    }

    @Test
    void isTokenValid_tokenSignedWithAnotherKey_returnsFalse() {
        SecretKey anotherKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(generateSecretKey()));
        String token = Jwts.builder()
                .subject("1")
                .claim("role", UserRole.ROLE_USER.name())
                .claim("tokenType", TokenType.ACCESS.name())
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(60)))
                .signWith(anotherKey)
                .compact();

        assertFalse(jwtService.isTokenValid(token, TokenType.ACCESS));
    }

    @Test
    void isTokenValid_expiredToken_returnsFalse() {
        SecretKey signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        String token = Jwts.builder()
                .subject("1")
                .claim("userId", 1L)
                .claim("role", UserRole.ROLE_USER.name())
                .claim("tokenType", TokenType.ACCESS.name())
                .issuedAt(Date.from(Instant.now().minusSeconds(120)))
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(signingKey)
                .compact();

        assertFalse(jwtService.isTokenValid(token, TokenType.ACCESS));
    }

    @Test
    void extractTokenId_refreshToken_returnsCorrectId() {
        UUID expectedTokenId = UUID.randomUUID();

        String token = jwtService.generateRefreshToken(1L, UserRole.ROLE_USER, expectedTokenId);

        assertEquals(expectedTokenId, jwtService.extractTokenId(token));
    }

    private String generateSecretKey() {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}