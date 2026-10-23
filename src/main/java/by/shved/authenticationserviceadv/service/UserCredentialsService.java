package by.shved.authenticationserviceadv.service;

import by.shved.authenticationserviceadv.dto.credentials.UserCredentialsRequest;

public interface UserCredentialsService {
    void saveCredentials(UserCredentialsRequest request);
}
