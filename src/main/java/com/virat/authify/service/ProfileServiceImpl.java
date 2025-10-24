package com.virat.authify.service;

import com.virat.authify.entity.UserEntity;
import com.virat.authify.io.ProfileRequest;
import com.virat.authify.io.ProfileResponse;
import com.virat.authify.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

@Service
@RequiredArgsConstructor
public class ProfileServiceImpl implements ProfileService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    @Override
    public ProfileResponse createProfile(ProfileRequest request) {
        UserEntity newProfile = convertToUserEntity(request);

        if (!userRepository.existsByEmail(request.getEmail())) {
            newProfile = userRepository.save(newProfile);
            return convertToProfileResponse(newProfile);
        }
        throw new ResponseStatusException(HttpStatus.CONFLICT, "Email already exists");
    }

    @Override
    public ProfileResponse getProfile(String email) {
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("username not found " + email));
        return convertToProfileResponse(existingUser);
    }

    @Override
    public void sendResetOtpEmail(String email) {
        UserEntity existingEntity = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("username not found " + email));

        String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 1000000));
        Long expiryTime = System.currentTimeMillis() + (15 * 60 * 1000); // 15 mins

        existingEntity.setReset0tp(otp);
        existingEntity.setReset0tpExpireAt(expiryTime);
        userRepository.save(existingEntity);

        try {
            emailService.sendResetOTP(existingEntity.getEmail(), otp);
        } catch (Exception e) {
            throw new RuntimeException("Unable to send email");
        }
    }

    @Override
    public void resetPassword(String email, String otp, String newPassword) {
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("username not found " + email));

        if (existingUser.getReset0tp() == null || !existingUser.getReset0tp().equals(otp)) {
            throw new RuntimeException("Invalid OTP");
        }
        if (existingUser.getReset0tpExpireAt() < System.currentTimeMillis()) {
            throw new RuntimeException("OTP expired");
        }

        existingUser.setPassword(passwordEncoder.encode(newPassword));
        existingUser.setReset0tp(null);
        existingUser.setReset0tpExpireAt(0L);

        userRepository.save(existingUser);
    }

    @Override
    public void sendOtp(String email) {
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("username not found " + email));

        if (Boolean.TRUE.equals(existingUser.getIsAccountVerified())) {
            return; // already verified
        }

        String otp = String.valueOf(ThreadLocalRandom.current().nextInt(100000, 1000000));
        Long expiryTime = System.currentTimeMillis() + (24 * 60 * 60 * 1000); // 24 hours

        existingUser.setVerify0tp(otp);
        existingUser.setVerify0tpExpireAt(expiryTime);
        userRepository.save(existingUser);

        try {
            emailService.sendOtpEmail(existingUser.getEmail(), otp);
        } catch (Exception e) {
            throw new RuntimeException("Unable to send email");
        }
    }

    @Override
    public void verifyOtp(String email, String otp) {
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("username not found " + email));

        // 1️⃣ Check if OTP is correct
        if (existingUser.getVerify0tp() == null || !existingUser.getVerify0tp().equals(otp)) {
            throw new RuntimeException("Invalid OTP");
        }

        // 2️⃣ Check if OTP expired
        if (existingUser.getVerify0tpExpireAt() == null || existingUser.getVerify0tpExpireAt() < System.currentTimeMillis()) {
            throw new RuntimeException("OTP expired");
        }

        // 3️⃣ Mark account as verified
        existingUser.setIsAccountVerified(true);

        // 4️⃣ Clear OTP fields after successful verification
        existingUser.setVerify0tp(null);
        existingUser.setVerify0tpExpireAt(null);

        // 5️⃣ Save updated user
        userRepository.save(existingUser);
    }

    @Override
    public String getLoggedInUserId(String email) {
        UserEntity existingUser = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("username not found " + email));
        return existingUser.getUserId();
    }

    // ===================== Helper Methods =====================

    private ProfileResponse convertToProfileResponse(UserEntity newProfile) {
        return ProfileResponse.builder()
                .name(newProfile.getName())
                .email(newProfile.getEmail())
                .userId(newProfile.getUserId())
                .isAccountVerified(newProfile.getIsAccountVerified())
                .build();
    }

    private UserEntity convertToUserEntity(ProfileRequest request) {
        return UserEntity.builder()
                .email(request.getEmail())
                .userId(UUID.randomUUID().toString())
                .name(request.getName())
                .password(passwordEncoder.encode(request.getPassword()))
                .isAccountVerified(false)
                .reset0tpExpireAt(0L)
                .verify0tp(null)
                .verify0tpExpireAt(0L)
                .reset0tp(null)
                .build();
    }
}
