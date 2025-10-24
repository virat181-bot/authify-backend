package com.virat.authify.service;

import com.virat.authify.io.ProfileRequest;
import com.virat.authify.io.ProfileResponse;

public interface ProfileService {

    ProfileResponse createProfile(ProfileRequest request);

    ProfileResponse getProfile(String email);

    void sendResetOtpEmail(String email);

    void resetPassword(String email, String otp, String newPassword);

    void sendOtp(String email);

    void verifyOtp(String email, String otp);

    // ✅ Add this missing method
    String getLoggedInUserId(String email);
}
