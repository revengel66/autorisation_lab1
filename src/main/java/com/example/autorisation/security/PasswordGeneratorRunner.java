package com.example.autorisation.security;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordGeneratorRunner implements CommandLineRunner {

    private Sha256PasswordEncoder passwordEncoder;

    public PasswordGeneratorRunner(Sha256PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
    @Override
    public void run(String... args) throws Exception {
        String pass = "admin1234";
        String encoded = passwordEncoder.encode(pass);
        System.out.println("Encoded password: " + encoded);

    }
}

