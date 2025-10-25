package com.example.autorisation.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LoginAttemptService {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoginAttemptService.class);
    private static final int MAX_ATTEMPTS = 3;

    private final Map<String, Integer> attemptsByUser = new ConcurrentHashMap<>();
    private final ApplicationTerminator applicationTerminator;

    public LoginAttemptService(ApplicationTerminator applicationTerminator) {
        this.applicationTerminator = applicationTerminator;
    }

    public void recordSuccessfulAttempt(String username) {
        if (username == null) {
            return;
        }
        String key = sanitize(username);
        if (key.isEmpty()) {
            return;
        }
        attemptsByUser.remove(key);
    }

    public int recordFailedAttempt(String username) {
        if (username == null || username.isBlank()) {
            return MAX_ATTEMPTS;
        }

        String key = sanitize(username);
        if (key.isEmpty()) {
            return MAX_ATTEMPTS;
        }
        int failedAttempts = attemptsByUser.merge(key, 1, Integer::sum);
        int attemptsLeft = Math.max(MAX_ATTEMPTS - failedAttempts, 0);

        if (failedAttempts >= MAX_ATTEMPTS) {
            LOGGER.warn("Получена {} неверная попытка входа для пользователя '{}'. Завершаем приложение.", failedAttempts, username);
            applicationTerminator.scheduleShutdown();
        }

        return attemptsLeft;
    }

    private String sanitize(String raw) {
        return raw.trim();
    }
}
