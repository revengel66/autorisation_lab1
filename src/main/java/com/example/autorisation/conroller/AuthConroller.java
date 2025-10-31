package com.example.autorisation.conroller;

import com.example.autorisation.repository.AdminRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthConroller {

    private final AdminRepository adminRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthConroller(AdminRepository adminRepository, PasswordEncoder passwordEncoder) {
        this.adminRepository = adminRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/login")
    public String login() {
        return "auth/login";
    }

}
