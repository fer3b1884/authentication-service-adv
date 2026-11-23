package by.shved.authenticationserviceadv.config;

import by.shved.authenticationserviceadv.entity.UserCredentialsEntity;
import by.shved.authenticationserviceadv.entity.UserRole;
import by.shved.authenticationserviceadv.repository.UserCredentialsRepository;
import by.shved.authenticationserviceadv.config.property.AdminProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Component
@RequiredArgsConstructor
public class AdminInitializer implements ApplicationRunner {
    private final UserCredentialsRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final AdminProperties adminProperties;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        var existingAdmin = repository.findByLogin(adminProperties.login());
        if (existingAdmin.isPresent()) {
            UserCredentialsEntity admin = existingAdmin.get();
            if (!admin.getUserId().equals(adminProperties.userId()) || admin.getRole() != UserRole.ROLE_ADMIN) {
                throw new IllegalStateException("Configured admin login belongs to another account");
            }
            log.info("Admin credentials already exist: userId={}", admin.getUserId());
            return;
        }
        if (repository.existsByUserId(adminProperties.userId())) {
            throw new IllegalStateException("Configured admin userId is already assigned to another account");
        }
        UserCredentialsEntity admin = new UserCredentialsEntity();
        admin.setUserId(adminProperties.userId());
        admin.setLogin(adminProperties.login());
        admin.setPasswordHash(passwordEncoder.encode(adminProperties.password()));
        admin.setRole(UserRole.ROLE_ADMIN);
        repository.save(admin);
        log.info("Admin credentials initialized: userId={}", adminProperties.userId());
    }
}
