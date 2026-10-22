package by.shved.authenticationserviceadv.repository;

import by.shved.authenticationserviceadv.entity.UserCredentialsEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserCredentialsRepository extends JpaRepository<UserCredentialsEntity, Long> {
}
