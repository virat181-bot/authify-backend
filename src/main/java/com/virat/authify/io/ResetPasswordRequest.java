package com.virat.authify.io;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResetPasswordRequest {
    @NotBlank(message = "email is required")
    private String email;
    @NotBlank(message = "otp is required")
    private String otp;
    @NotBlank(message = "pasword is required")
    private String newPassword;
}

