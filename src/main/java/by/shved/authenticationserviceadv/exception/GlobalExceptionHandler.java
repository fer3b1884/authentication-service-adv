package by.shved.authenticationserviceadv.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {
    @ExceptionHandler(DuplicateResourceException.class)
    public ProblemDetail handleDuplicate(DuplicateResourceException exception, HttpServletRequest request) {
        log.warn("Duplicate resource: {} {} - {}", request.getMethod(), request.getRequestURI(), exception.getMessage());
        return createProblemDetail(
                HttpStatus.CONFLICT,
                exception.getMessage(),
                "Duplicate resource",
                request
        );
    }

    @ExceptionHandler({InvalidTokenException.class, BadCredentialsException.class})
    public ProblemDetail handleUnauthorized(RuntimeException exception, HttpServletRequest request) {
        log.warn("Authentication failed: {} {} - {}", request.getMethod(), request.getRequestURI(), exception.getMessage());
        return createProblemDetail(
                HttpStatus.UNAUTHORIZED,
                exception.getMessage(),
                "Authentication failed",
                request
        );
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ProblemDetail handleDataIntegrityViolation(DataIntegrityViolationException exception, HttpServletRequest request) {
        log.warn("Data integrity violation: {} {}", request.getMethod(), request.getRequestURI());
        return createProblemDetail(
                HttpStatus.CONFLICT,
                "The request conflicts with existing data",
                "Data integrity violation",
                request
        );
    }

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleUnexpected(Exception exception, HttpServletRequest request) {
        log.error("Unexpected error: {} {}", request.getMethod(), request.getRequestURI(), exception);
        return createProblemDetail(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred",
                "Internal server error",
                request
        );
    }

    private ProblemDetail createProblemDetail(HttpStatus status, String detail, String title, HttpServletRequest request) {
        ProblemDetail problemDetail = ProblemDetail.forStatusAndDetail(status, detail);
        problemDetail.setTitle(title);
        problemDetail.setInstance(URI.create(request.getRequestURI()));
        return problemDetail;
    }
}
