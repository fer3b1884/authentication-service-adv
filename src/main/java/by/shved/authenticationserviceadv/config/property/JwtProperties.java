package by.shved.authenticationserviceadv.config.property;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "security.jwt")
public record JwtProperties(
        @NotBlank(message = "JWT secret must not be blank")
        String secret,

        @NotNull
        @DurationMin(millis = 1)
        Duration accessTokenExpiration,

        @NotNull
        @DurationMin(millis = 1)
        Duration refreshTokenExpiration
) {
}
