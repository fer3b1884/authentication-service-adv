package by.shved.authenticationserviceadv.service;

import by.shved.authenticationserviceadv.dto.credentials.LoginRequest;
import by.shved.authenticationserviceadv.dto.token.RefreshTokenRequest;
import by.shved.authenticationserviceadv.dto.token.TokenResponse;
import by.shved.authenticationserviceadv.dto.token.TokenValidationResponse;

public interface AuthenticationService {
    TokenResponse login(LoginRequest request);
    TokenResponse refresh(RefreshTokenRequest request);
    TokenValidationResponse validateToken(String token);
}
