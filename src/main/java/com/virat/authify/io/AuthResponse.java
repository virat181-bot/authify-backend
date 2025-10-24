package com.virat.authify.io;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.web.bind.annotation.GetMapping;





@Getter
@AllArgsConstructor
public class AuthResponse {

    private String email;
    private String token;
}
