package by.shved.authenticationserviceadv.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.nio.charset.StandardCharsets;

public class PasswordLengthValidator implements ConstraintValidator<PasswordLength, String> {
    private static final int MIN_CHARACTERS = 8;
    private static final int MAX_BYTES = 72;

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null || password.isBlank()) {
            return true;
        }
        int characterCount = password.codePointCount(0, password.length());
        int byteCount = password.getBytes(StandardCharsets.UTF_8).length;
        return characterCount >= MIN_CHARACTERS && byteCount <= MAX_BYTES;
    }
}
