package com.virat.authify.io;

import jakarta.persistence.Column;
import jakarta.validation.constraints.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@Data
@NoArgsConstructor
public class ProfileRequest {
    @NotBlank(message = "name should not empty")
    private String name;
    @Email(message = "enter a valid email")
    @NotNull(message = "email not empty")
    private String email;
    @Size(min=6,message = "alleast 6 characters have to there")
    private String password;
}
