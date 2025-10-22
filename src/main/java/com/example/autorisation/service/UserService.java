package com.example.autorisation.service;

import com.example.autorisation.entity.User;
import com.example.autorisation.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public User getUserById(Long id) {
        return userRepository.findById(id).orElse(null);
    }

    public void saveUser(User user) {
        if (user.getId() != null) {
            User existing = userRepository.findById(user.getId()).orElse(null);
            if (existing != null) {
                user.setUsername(existing.getUsername());
                user.setPassword(existing.getPassword());
            }
        }
        userRepository.save(user);
    }

    public void updatePassword(Long userId, String rawPassword) {
        if (rawPassword == null || rawPassword.isBlank()) {
            throw new IllegalArgumentException("Password must not be empty");
        }
        User existing = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));
        existing.setPassword(passwordEncoder.encode(rawPassword));
        userRepository.save(existing);
    }

    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}
