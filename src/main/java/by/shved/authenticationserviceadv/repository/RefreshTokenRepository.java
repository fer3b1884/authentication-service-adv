package by.shved.authenticationserviceadv.repository;

import by.shved.authenticationserviceadv.entity.RefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {
    Optional<RefreshTokenEntity> findByTokenId(UUID tokenId);

    @Modifying
    @Query("""
            UPDATE RefreshTokenEntity rt
            SET rt.revoked = true
            WHERE rt.tokenId = :tokenId
                AND rt.userId = :userId
                AND rt.revoked = false
                AND rt.expiresAt > :now
            """)
    int revokeIfValid(
            @Param("tokenId") UUID tokenId,
            @Param("userId") Long userId,
            @Param("now") LocalDateTime now
    );

    @Modifying
    @Query("""
            DELETE FROM RefreshTokenEntity rt
            WHERE rt.expiresAt < :now
            """)
    int deleteExpiredTokens(@Param("now") LocalDateTime now);

    @Modifying
    @Query("""
            UPDATE RefreshTokenEntity rt
            SET rt.revoked = true
            WHERE rt.userId = :userId
                AND rt.revoked = false
            """)
    int revokeAllActiveTokensByUserId(@Param("userId") Long userId);
}
