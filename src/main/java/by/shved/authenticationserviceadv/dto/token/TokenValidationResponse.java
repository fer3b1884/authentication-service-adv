package by.shved.authenticationserviceadv.dto.token;

public record TokenValidationResponse(
        boolean valid,
        Long userId,
        String role
) {
}
