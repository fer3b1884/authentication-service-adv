package by.shved.authenticationserviceadv.dto.credentials;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "Login must not be blank")
        @Size(max = 100, message = "Login must not exceed 100 characters")
        String login,

        @NotBlank(message = "Password must not be blank")
        @Size(max = 100, message = "Password must not exceed 100 characters")
        String password
) {
}
