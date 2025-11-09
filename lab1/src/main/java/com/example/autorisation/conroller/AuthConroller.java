package com.example.autorisation.conroller;

import com.example.autorisation.repository.AdminRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.io.IOException;

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

    @PostMapping("/login")
    public void сonfirmPassword(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String password = request.getParameter("password");
        String confirmPassword = request.getParameter("confirmPassword");
        if (password == null || confirmPassword == null) {
            response.sendRedirect("/login?confirmError");
        }
        if (!password.equals(confirmPassword)) {
            response.sendRedirect("/login?confirmError");
        } else {
            request.getRequestDispatcher("/login-process").forward(request, response);
        }

    }
}
