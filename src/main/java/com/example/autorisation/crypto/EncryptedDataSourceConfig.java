package com.example.autorisation.crypto;

import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import javax.sql.DataSource;

@Configuration
public class EncryptedDataSourceConfig {
    private final DatabaseEncryptionService encryptionService;
    private final Environment environment;

    public EncryptedDataSourceConfig(DatabaseEncryptionService encryptionService, Environment environment){
        this.encryptionService = encryptionService;
        this.environment = environment;
    }

    @Bean
    public DataSource dataSource() {
        encryptionService.ensureDatabaseReady();

        String url = environment.getRequiredProperty("spring.datasource.url");
        String driverClassName = environment.getProperty("spring.datasource.driver-class-name");

        DataSourceBuilder<?> builder = DataSourceBuilder.create();
        if (driverClassName != null && !driverClassName.isBlank()) {
            builder.driverClassName(driverClassName);
        }
        builder.url(url);
        return builder.build();
    }


}
