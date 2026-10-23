package by.shved.authenticationserviceadv.service.jwt;

import by.shved.authenticationserviceadv.entity.TokenType;
import by.shved.authenticationserviceadv.entity.UserRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtService {
    @Value("${security.jwt.secret}")
    private String secret;
    @Value("${security.jwt.access-token-expiration}")
    private long accessTokenExpiration;
    @Value("${security.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    public String generateAccessToken(Long userId, UserRole role) {
        return generateToken(userId, role, TokenType.ACCESS, accessTokenExpiration, null);
    }

    public String generateRefreshToken(Long userId, UserRole role, UUID tokenId) {
        return generateToken(userId, role, TokenType.REFRESH, refreshTokenExpiration, tokenId);
    }

    private String generateToken(Long userId, UserRole role, TokenType tokenType,
                                 long expiration, UUID tokenId) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusMillis(expiration);
        var builder = Jwts.builder()
                .subject(userId.toString())
                .claim("userId", userId)
                .claim("role", role.name())
                .claim("tokenType", tokenType.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt));
        if (tokenId != null) {
            builder.id(tokenId.toString());
        }
        return builder
                .signWith(getSigningKey())
                .compact();
    }

    public boolean isTokenValid(String token, TokenType expectedTokenType) {
        try {
            Claims claims = parseClaims(token);
            Long userId = Long.valueOf(claims.getSubject());
            UserRole.valueOf(claims.get("role", String.class));
            TokenType tokenType = TokenType.valueOf(claims.get("tokenType", String.class));
            if (userId <= 0 || tokenType != expectedTokenType) {
                return false;
            }
            if (expectedTokenType == TokenType.REFRESH) {
                UUID.fromString(claims.getId());
            }
            return true;
        } catch (JwtException | IllegalArgumentException | NullPointerException exception) {
            return false;
        }
    }

    public Long extractUserId(String token) {
        return Long.valueOf(parseClaims(token).getSubject());
    }

    public UserRole extractRole(String token) {
        return UserRole.valueOf(parseClaims(token).get("role", String.class));
    }

    public TokenType extractTokenType(String token) {
        return TokenType.valueOf(parseClaims(token).get("tokenType", String.class));
    }

    public UUID extractTokenId(String token) {
        return UUID.fromString(parseClaims(token).getId());
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }
}
