package com.example.autorisation.service;

import com.example.autorisation.entity.Admin;
import com.example.autorisation.entity.User;
import com.example.autorisation.repository.AdminRepository;
import com.example.autorisation.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AdminService implements UserDetailsService {


    @Autowired
    private AdminRepository adminRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public List<Admin> getAllUsers() {
        return adminRepository.findAll();
    }
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return adminRepository.findByUsername(username)
                .map(admin -> (UserDetails) admin)
                .orElseGet(() -> userRepository.findByUsername(username)
                        .map(user -> (UserDetails) user)
                        .orElseThrow(() -> new UsernameNotFoundException(username)));
    }

    public Admin getAdminById(Long id) {
        return adminRepository.findById(id).orElse(null);
    }

    public void updatePassword(Long adminId, String rawPassword) {
        if (rawPassword == null || rawPassword.isBlank()) {
            throw new IllegalArgumentException("Пароль не может быть пустым");
        }
        Admin existing = adminRepository.findById(adminId)
                .orElseThrow(() -> new IllegalArgumentException("Админ не найден: " + adminId));
        existing.setPassword(passwordEncoder.encode(rawPassword));
        adminRepository.save(existing);
    }
}
