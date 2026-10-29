package by.shved.authenticationserviceadv.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.http.HttpRequest;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(DuplicateResourceException.class)
    public ResponseEntity<String> handleDuplicate(DuplicateResourceException exception, HttpServletRequest request) {
        log.warn("Duplicate resource: {} {} - {}", request.getMethod(), request.getRequestURI(), exception.getMessage());
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(exception.getMessage());
    }

    @ExceptionHandler({InvalidTokenException.class, BadCredentialsException.class})
    public ResponseEntity<String> handleUnauthorized(RuntimeException exception, HttpServletRequest request) {
        log.warn("Authentication failed: {} {} - {}", request.getMethod(), request.getRequestURI(), exception.getMessage());
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(exception.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<String> handleValidation(MethodArgumentNotValidException exception, HttpServletRequest request) {
        String errorMessage = exception.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .collect(Collectors.joining(", "));
        log.warn("Validation failed: {} {} - {}", request.getMethod(), request.getRequestURI(), errorMessage);
        return ResponseEntity
                .badRequest()
                .body("Validation errors: " + errorMessage);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleUnexpected(Exception exception, HttpServletRequest request) {
        log.error("Unexpected error: {} {}", request.getMethod(), request.getRequestURI(), exception);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("An unexpected error occurred");
    }
}
