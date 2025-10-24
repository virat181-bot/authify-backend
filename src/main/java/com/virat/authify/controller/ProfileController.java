package com.virat.authify.controller;

import com.virat.authify.io.ProfileRequest;
import com.virat.authify.io.ProfileResponse;
import com.virat.authify.service.EmailService;
import com.virat.authify.service.ProfileService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1.0")
@RequiredArgsConstructor
public class ProfileController {
private final   ProfileService profileService;
private  final EmailService emailService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ProfileResponse register(@Valid @RequestBody ProfileRequest request){
     ProfileResponse response= profileService.createProfile(request);
     emailService.sendWelcomeEmail(response.getEmail(),response.getName());
     return response;

    }
//     @GetMapping("/test")
//    public  String test(){
//        return  "Auth is working";
//     }
@GetMapping("/profile")
    public  ProfileResponse getProfile(@CurrentSecurityContext(expression = "authentication?.name")String email){
     return     profileService.getProfile(email);
}

    @GetMapping("/is-authenticated")
    public ResponseEntity<Boolean> isAuthenticated(@CurrentSecurityContext(expression = "authentication?.name") String email) {
        return ResponseEntity.ok(email != null);
    }

}
