package by.shved.authenticationserviceadv.controller;

import by.shved.authenticationserviceadv.dto.credentials.LoginRequest;
import by.shved.authenticationserviceadv.dto.credentials.UserCredentialsRequest;
import by.shved.authenticationserviceadv.dto.token.RefreshTokenRequest;
import by.shved.authenticationserviceadv.dto.token.TokenResponse;
import by.shved.authenticationserviceadv.dto.token.TokenValidationResponse;
import by.shved.authenticationserviceadv.service.AuthenticationService;
import by.shved.authenticationserviceadv.service.UserCredentialsService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authService;
    private final UserCredentialsService userCredentialsService;

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    @PostMapping("/validate")
    public ResponseEntity<TokenValidationResponse> validateToken(@RequestHeader(value = HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        if (!authorizationHeader.startsWith("Bearer ") || authorizationHeader.substring(7).isBlank()) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new TokenValidationResponse(false, null, null));
        }
        String token = authorizationHeader.substring(7).trim();
        TokenValidationResponse response = authService.validateToken(token);
        if (!response.valid()) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(response);
        }
        return ResponseEntity.ok(response);
    }

    @PostMapping("/credentials")
    public ResponseEntity<Void> saveCredentials(@Valid @RequestBody UserCredentialsRequest request) {
        userCredentialsService.saveCredentials(request);
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .build();
    }
}
