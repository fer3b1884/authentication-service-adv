package by.shved.authenticationserviceadv.dto.credentials;

import by.shved.authenticationserviceadv.validation.PasswordLength;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank(message = "Login must not be blank")
        @Size(min=3, max = 100, message = "Login must not exceed 100 characters")
        String login,

        @NotBlank(message = "Password must not be blank")
        @PasswordLength
        String password
) {
}
