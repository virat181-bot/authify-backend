package com.virat.authify.service;

import com.virat.authify.entity.UserEntity;
import com.virat.authify.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
@RequiredArgsConstructor
public class AppUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {


     UserEntity existngUser= userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("Email not found for email"+email));

     return new User(existngUser.getEmail(),existngUser.getPassword(),new ArrayList<>());
    }
}
