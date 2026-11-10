package by.shved.authenticationserviceadv.service.impl;

import by.shved.authenticationserviceadv.dto.credentials.UserCredentialsRequest;
import by.shved.authenticationserviceadv.entity.UserCredentialsEntity;
import by.shved.authenticationserviceadv.exception.DuplicateResourceException;
import by.shved.authenticationserviceadv.repository.UserCredentialsRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserCredentialsServiceImplTest {
    @Mock
    private UserCredentialsRepository userCredentialsRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @InjectMocks
    private UserCredentialsServiceImpl userCredentialsService;

    private UserCredentialsRequest request;

    @BeforeEach
    void setUp() {
        request = new UserCredentialsRequest(1L, "test-user", "password123");
    }

    @Test
    void saveCredentials_validRequest_savesCredentials() {
        when(userCredentialsRepository.existsByLogin("test-user")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("encoded-password");

        userCredentialsService.saveCredentials(request);

        verify(userCredentialsRepository).existsByLogin("test-user");
        verify(passwordEncoder).encode("password123");
        verify(userCredentialsRepository).save(any(UserCredentialsEntity.class));
    }


    @Test
    void saveCredentials_existingLogin_throwsException() {
        when(userCredentialsRepository.existsByLogin("test-user")).thenReturn(true);

        assertThrows(DuplicateResourceException.class, () -> userCredentialsService.saveCredentials(request));
        verify(userCredentialsRepository, never()).save(any());
        verify(passwordEncoder, never()).encode(anyString());
    }
}