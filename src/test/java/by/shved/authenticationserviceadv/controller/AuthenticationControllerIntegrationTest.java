package by.shved.authenticationserviceadv.controller;

import by.shved.authenticationserviceadv.entity.UserCredentialsEntity;
import by.shved.authenticationserviceadv.entity.UserRole;
import by.shved.authenticationserviceadv.repository.UserCredentialsRepository;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.springframework.http.MediaType;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
class AuthenticationControllerIntegrationTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserCredentialsRepository userCredentialsRepository;

    @Autowired
    private org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"));

    private static final String JWT_SECRET = generateJwtSecret();

    private static String generateJwtSecret() {
        byte[] key = new byte[32];
        new java.security.SecureRandom().nextBytes(key);
        return java.util.Base64.getEncoder().encodeToString(key);
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", postgres::getJdbcUrl);
        registry.add("DB_USERNAME", postgres::getUsername);
        registry.add("DB_PASSWORD", postgres::getPassword);
        registry.add("JWT_SECRET", () -> JWT_SECRET);
    }

    @BeforeEach
    void setUp() {
        userCredentialsRepository.deleteAll();

        UserCredentialsEntity user = new UserCredentialsEntity();
        user.setUserId(1L);
        user.setLogin("test-user");
        user.setPasswordHash(passwordEncoder.encode("password123"));
        user.setRole(UserRole.ROLE_USER);

        userCredentialsRepository.saveAndFlush(user);
    }

    @Test
    void login_whenCredentialsAreValid_returnsTokens() throws Exception {
        String request = """
                {
                    "login": "test-user",
                    "password": "password123"
                }
                """;

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").isNumber());
    }

    @Test
    void login_whenPasswordIsInvalid_returnsUnauthorized() throws Exception {
        String request = """
                {
                  "login": "test-user",
                  "password": "wrong-password"
                }
                """;

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_whenUserDoesNotExist_returnsUnauthorized() throws Exception {
        String request = """
                {
                  "login": "unknown-user",
                  "password": "password123"
                }
                """;

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_whenLoginIsBlank_returnsBadRequest() throws Exception {
        String request = """
                {
                  "login": "",
                  "password": "password123"
                }
                """;

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isBadRequest());
    }

    @Test
    void login_whenPasswordIsBlank_returnsBadRequest() throws Exception {
        String request = """
                {
                  "login": "test-user",
                  "password": ""
                }
                """;

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isBadRequest());
    }


    @Test
    void validate_whenAccessTokenIsValid_returnsValid() throws Exception {
        String accessToken = obtainAccessToken();

        mockMvc.perform(post("/auth/validate")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.userId").value(1))
                .andExpect(jsonPath("$.role").value("ROLE_USER"));
    }

    @Test
    void validate_whenTokenIsInvalid_returnsUnauthorized() throws Exception {
        mockMvc.perform(post("/auth/validate")
                        .header("Authorization", "Bearer invalid-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refresh_whenRefreshTokenIsValid_returnsNewTokens() throws Exception {
        String refreshToken = obtainRefreshToken();
        String request = """
                {
                  "refreshToken": "%s"
                }
                """.formatted(refreshToken);

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").isNumber());
    }

    @Test
    void refresh_whenRefreshTokenIsInvalid_returnsUnauthorized() throws Exception {
        String request = """
                {
                  "refreshToken": "invalid-token"
                }
                """;

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refresh_whenRefreshTokenIsBlank_returnsBadRequest() throws Exception {
        String request = """
                {
                  "refreshToken": ""
                }
                """;

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isBadRequest());
    }

    private String obtainAccessToken() throws Exception {
        String request = """
                {
                  "login": "test-user",
                  "password": "password123"
                }
                """;

        String response = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        return JsonMapper.builder()
                .build()
                .readTree(response)
                .get("accessToken")
                .asText();
    }

    private String obtainRefreshToken() throws Exception {
        String request = """
                {
                  "login": "test-user",
                  "password": "password123"
                }
                """;

        String response = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(request))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        return JsonMapper.builder()
                .build()
                .readTree(response)
                .get("refreshToken")
                .asText();
    }
}