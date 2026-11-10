package by.shved.authenticationserviceadv.repository;

import by.shved.authenticationserviceadv.entity.UserCredentialsEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserCredentialsRepository extends JpaRepository<UserCredentialsEntity, Long> {
    boolean existsByLogin(String login);
    Optional<UserCredentialsEntity> findByLogin(String login);
    Optional<UserCredentialsEntity> findByUserId(Long userId);
}
