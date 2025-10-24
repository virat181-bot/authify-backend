package com.virat.authify.controller;


import com.virat.authify.io.AuthRequest;
import com.virat.authify.io.AuthResponse;
import com.virat.authify.io.ResetPasswordRequest;
import com.virat.authify.service.AppUserDetailsService;
import com.virat.authify.service.ProfileService;
import com.virat.authify.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("api/v1.0")
@RequiredArgsConstructor
public class AuthController {


    private  final AuthenticationManager authenticationManager;
    private final AppUserDetailsService appUserDetailsService;
    private final JwtUtil jwtUtil;
    private  final ProfileService profileService;


    @PostMapping("/login")
    public ResponseEntity<?>login(@RequestBody AuthRequest request){
        try{
            authenticate(request.getEmail(),request.getPassword());
          final UserDetails userDetails= appUserDetailsService.loadUserByUsername(request.getEmail());
         final String jwtToken= jwtUtil.generateToken(userDetails);
                 ResponseCookie cookie=ResponseCookie.from("JWT",jwtToken)
                         .httpOnly(true)
                         .path("/")
                         .maxAge(Duration.ofDays(1))
                         .sameSite("Strict")
                         .build();
         return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
            .body(new AuthResponse(request.getEmail(),jwtToken));
        }catch (BadCredentialsException ex){
            Map<String,Object> error = new HashMap<>();
            error.put("error",true);
            error.put("message","Bad credentials");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);

        } catch (DisabledException ex){
            Map<String,Object> error = new HashMap<>();
            error.put("error",true);
            error.put("message","Account is disabled");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);

        } catch (Exception ex){
            Map<String,Object> error = new HashMap<>();
            ex.printStackTrace();
            error.put("error",true);
            error.put("message","Authentication is failed");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);

        }


    }

    private void authenticate(String email, String password) {

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email,password));
    }

@PostMapping("/send-reset-otp")
    public  void sendResetOTP(@RequestParam String email){
        try {
            profileService.sendResetOtpEmail(email);
        }catch (Exception e){
throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,e.getMessage());
        }
}
@PostMapping("/reset-password")
public  void resetPassword(@Valid @RequestBody ResetPasswordRequest request){

        try{
            profileService.resetPassword(request.getEmail(), request.getOtp(), request.getNewPassword());
        }catch (Exception e){
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,e.getMessage());
        }

}

    @PostMapping("/send-otp")
    public void sendVerifyOtp(@CurrentSecurityContext(expression = "authentication?.name") String email) {
        try {
            profileService.sendOtp(email);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }
    @PostMapping("/verify-otp")
    public ResponseEntity<Map<String, Object>> verifyEmail(
            @RequestBody Map<String, Object> request,
            @CurrentSecurityContext(expression = "authentication?.name") String email) {

        if (request.get("otp") == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "OTP is required");
        }

        try {
            profileService.verifyOtp(email, request.get("otp").toString());

            // ✅ Return success and optionally user data
            Map<String, Object> response = new HashMap<>();
            response.put("message", "OTP verified successfully");
            response.put("emailVerified", true); // optional flag for frontend

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }


    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String jwtToken = authHeader.substring(7); // Extract the token
            jwtUtil.addToBlacklist(jwtToken); // Add token 
        }

        ResponseCookie cookie = ResponseCookie.from("JWT", "")
                .httpOnly(true)
                .secure(true) // Match the secure flag of the original cookie
                .path("/")
                .maxAge(0)
                .sameSite("Strict")
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body("Logged out successfully");
    }
}
