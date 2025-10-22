package com.example.autorisation.conroller;

import com.example.autorisation.entity.Admin;
import com.example.autorisation.entity.User;
import com.example.autorisation.repository.AdminRepository;
import com.example.autorisation.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class AuthConroller {

    @Autowired
    private AdminRepository adminRepository;

    @GetMapping("/login")
    public String login() {
        return "auth/login";
    }

}
