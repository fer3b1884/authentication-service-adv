package by.shved.authenticationserviceadv.service.impl;

import by.shved.authenticationserviceadv.dto.credentials.UserCredentialsRequest;
import by.shved.authenticationserviceadv.entity.UserCredentialsEntity;
import by.shved.authenticationserviceadv.entity.UserRole;
import by.shved.authenticationserviceadv.exception.DuplicateResourceException;
import by.shved.authenticationserviceadv.repository.UserCredentialsRepository;
import by.shved.authenticationserviceadv.service.UserCredentialsService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserCredentialsServiceImpl implements UserCredentialsService {
    private final UserCredentialsRepository userCredentialsRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void saveCredentials(UserCredentialsRequest request) {
        if (userCredentialsRepository.existsByLogin(request.login())) {
            throw new DuplicateResourceException("Login is already taken");
        }
        UserCredentialsEntity credentials = new UserCredentialsEntity();
        credentials.setUserId(request.userId());
        credentials.setLogin(request.login());
        credentials.setPasswordHash(passwordEncoder.encode(request.password()));
        credentials.setRole(UserRole.ROLE_USER);
        log.info("User credentials created successfully: userId={}", request.userId());
        userCredentialsRepository.save(credentials);
    }
}
