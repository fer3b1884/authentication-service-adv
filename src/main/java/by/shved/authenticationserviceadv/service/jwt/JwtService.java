package by.shved.authenticationserviceadv.service.jwt;

import by.shved.authenticationserviceadv.config.property.JwtProperties;
import by.shved.authenticationserviceadv.entity.TokenType;
import by.shved.authenticationserviceadv.entity.UserRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
public class JwtService {
    private static final String CLAIM_ROLE = "role";
    private static final String CLAIM_TOKEN_TYPE = "tokenType";

    private final SecretKey signingKey;
    private final Duration accessTokenExpiration;
    private final Duration refreshTokenExpiration;
    private final JwtParser jwtParser;

    public JwtService(JwtProperties jwtProperties){
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.secret()));
        this.accessTokenExpiration = jwtProperties.accessTokenExpiration();
        this.refreshTokenExpiration = jwtProperties.refreshTokenExpiration();
        this.jwtParser = Jwts.parser()
                .verifyWith(signingKey)
                .build();
    }

    public String generateAccessToken(Long userId, UserRole role, UUID tokenId) {
        return generateToken(userId, role, TokenType.ACCESS, accessTokenExpiration, tokenId);
    }

    public String generateRefreshToken(Long userId, UserRole role, UUID tokenId) {
        return generateToken(userId, role, TokenType.REFRESH, refreshTokenExpiration, tokenId);
    }

    private String generateToken(Long userId, UserRole role, TokenType tokenType, Duration expiration, UUID tokenId) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(expiration);
        return Jwts.builder()
                .id(tokenId.toString())
                .subject(userId.toString())
                .claim(CLAIM_ROLE, role.name())
                .claim(CLAIM_TOKEN_TYPE, tokenType.name())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .signWith(signingKey)
                .compact();
    }

    public Optional<JwtPayload> parseAndValidate(String token, TokenType expectedTokenType) {
        if (token == null || token.isBlank() || expectedTokenType == null) {
            return Optional.empty();
        }
        try {
            Claims claims = parseClaims(token);
            String subject = claims.getSubject();
            String idStr = claims.getId();
            String roleStr = claims.get(CLAIM_ROLE, String.class);
            String typeStr = claims.get(CLAIM_TOKEN_TYPE, String.class);
            Date expiration = claims.getExpiration();
            if (subject == null || idStr == null || roleStr == null || typeStr == null || expiration == null) {
                return Optional.empty();
            }
            Long userId = Long.valueOf(subject);
            UUID tokenId = UUID.fromString(idStr);
            UserRole role = UserRole.valueOf(roleStr);
            TokenType tokenType = TokenType.valueOf(typeStr);
            if (userId <= 0 || tokenType != expectedTokenType) {
                return Optional.empty();
            }
            return Optional.of(new JwtPayload(userId, role, tokenType, tokenId, expiration.toInstant()));
        } catch (JwtException | IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    private Claims parseClaims(String token) {
        return jwtParser
                .parseSignedClaims(token)
                .getPayload();
    }
}
