package com.example.autorisation.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.stereotype.Component;

import java.util.concurrent.atomic.AtomicBoolean;

@Component
public class ApplicationTerminator {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApplicationTerminator.class);
    private final ConfigurableApplicationContext context;
    private final AtomicBoolean shutdownScheduled = new AtomicBoolean(false);

    public ApplicationTerminator(ConfigurableApplicationContext context) {
        this.context = context;
    }

    public void scheduleShutdown() {
        if (!shutdownScheduled.compareAndSet(false, true)) {
            return;
        }
        Thread shutdownThread = new Thread(this::shutdown, "login-attempt-shutdown");
        shutdownThread.setDaemon(false);
        shutdownThread.start();
    }

    private void shutdown() {
        try {
            Thread.sleep(500);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        LOGGER.error("Останавливаем приложение по условию ТЗ (три неудачные попытки ввода пароля).");
        context.close();
        System.exit(0);
    }
}
