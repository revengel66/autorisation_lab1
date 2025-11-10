package com.example.autorisation.service;

import com.example.autorisation.crypto.DatabaseEncryptionService;
import com.example.autorisation.entity.Admin;
import com.example.autorisation.repository.AdminRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DefaultAdminInitializer implements ApplicationRunner {
    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultAdminInitializer.class);
    private static final String DEFAULT_ADMIN_USERNAME = "ADMIN";

    private final DatabaseEncryptionService databaseEncryptionService;
    private final AdminRepository adminRepository;
    private final PasswordEncoder passwordEncoder;

    public DefaultAdminInitializer(DatabaseEncryptionService databaseEncryptionService,
                                   AdminRepository adminRepository,
                                   PasswordEncoder passwordEncoder) {
        this.databaseEncryptionService = databaseEncryptionService;
        this.adminRepository = adminRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!databaseEncryptionService.consumeDatabaseJustCreatedFlag()) {
            return;
        }
        if (adminRepository.findByUsername(DEFAULT_ADMIN_USERNAME).isPresent()) {
            LOGGER.info("Администратор {} уже существует, пропускаем автосоздание.", DEFAULT_ADMIN_USERNAME);
            return;
        }
        Admin admin = new Admin();
        admin.setUsername(DEFAULT_ADMIN_USERNAME);
        admin.setPassword(passwordEncoder.encode(""));
        admin.setMonth(0);
        admin.setPasswordExpiresAt(null);
        adminRepository.save(admin);
        LOGGER.info("Создан администратор {} с пустым паролем для первого входа.", DEFAULT_ADMIN_USERNAME);
    }
}
