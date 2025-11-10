package com.example.autorisation.crypto;

import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.file.*;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class DatabaseEncryptionService{
    private static final Logger LOGGER = LoggerFactory.getLogger(DatabaseEncryptionService.class);
    private static final byte[] SQLITE_HEADER = "SQLite format 3\u0000".getBytes(StandardCharsets.US_ASCII);

    private final Path encryptedPath;
    private final Path decryptedPath;
    private final byte[] key;
    private final byte[] iv;
    private final Object lock = new Object();
    private final AtomicBoolean databaseJustCreated = new AtomicBoolean(false);

    public DatabaseEncryptionService(@Value("${app.db.encrypted-path}") String encryptedPath, @Value("${app.db.decrypted-path}") String decryptedPath, @Value("${app.db.des.key}") String keyHex, @Value("${app.db.des.iv}") String ivHex){
        this.encryptedPath = resolvePath(encryptedPath);
        this.decryptedPath = resolvePath(decryptedPath);
        this.key = decodeHex("app.db.des.key", keyHex);
        this.iv = decodeHex("app.db.des.iv", ivHex);
    }

    // Метод для подготовки базы данных при запуске приложения
    public void ensureDatabaseReady() {
        synchronized (lock) {
            try {
                if (Files.exists(encryptedPath)) {
                    LOGGER.info("Расшифровываем БД из {}.", encryptedPath);
                    wipeAndDelete(encryptedPath.resolveSibling("auth.db.enc.tmp"));
                    Path tempDecrypted = createTempSibling(decryptedPath, ".tmp");
                    try {
                        wipeAndDelete(tempDecrypted);
                        ensureParentExists(tempDecrypted);
                        transformFile(encryptedPath, tempDecrypted, Cipher.DECRYPT_MODE);
                        moveWithRetry(tempDecrypted, decryptedPath);
                        ensureValidSqliteDatabaseOrRecreate(decryptedPath);
                    } finally {
                        wipeAndDelete(tempDecrypted);
                    }
                } else {
                    LOGGER.warn("Зашифрованный файл {} не найден. Создаём новую БД {}.", encryptedPath, decryptedPath);
                    initializeEmptyDatabase(decryptedPath);
                }
            } catch (IOException | GeneralSecurityException e) {
                throw new IllegalStateException("Не удалось подготовить базу данных.", e);
            }
        }
    }

    // Метод для проверки валидности SQLite-базы данных. Если база невалидна, пересоздаём её.
    // Невалидна, если файл отсутствует, имеет нулевой размер или неправильный заголовок.
    private void ensureValidSqliteDatabaseOrRecreate(Path candidate) throws IOException {
        if (isValidSqliteDatabase(candidate)) {
            return;
        }
        LOGGER.error("Файл {} не похож на валидную SQLite-базу. Пересоздаём файл. Проверьте значения APP_DB_DES_KEY и APP_DB_DES_IV.", candidate);
        initializeEmptyDatabase(candidate);
    }

    // Метод для проверки, является ли файл валидной SQLite-базой данных.
    private boolean isValidSqliteDatabase(Path candidate) throws IOException {
        if (!Files.exists(candidate)) {
            return false;
        }
        if (Files.size(candidate) == 0) {
            return true;
        }
        byte[] header = new byte[SQLITE_HEADER.length];
        // Читаем заголовок файла
        try (InputStream input = Files.newInputStream(candidate)) {
            int read = input.read(header);
            if (read < SQLITE_HEADER.length) {
                return false;
            }
        }
        return Arrays.equals(header, SQLITE_HEADER);
    }

    // Метод для инициализации новой пустой SQLite-базы данных.
    private void initializeEmptyDatabase(Path target) throws IOException {
        wipeAndDelete(target);
        ensureParentExists(target);
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new IOException("Драйвер SQLite не найден в classpath.", e);
        }
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + target);
             Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA user_version = 0");
        } catch (SQLException e) {
            throw new IOException("Не удалось создать новую базу данных: " + target, e);
        }
        databaseJustCreated.set(true);
    }

    // Метод, вызываемый при завершении работы приложения для шифрования базы данных
    @PreDestroy
    public void encryptOnShutdown() {
        synchronized (lock) {
            try {
                if (!Files.exists(decryptedPath)) {
                    LOGGER.warn("Файл расшифрованной БД {} не найден. Пропускаем шифрование.", decryptedPath);
                    return;
                }
                LOGGER.info("Шифруем БД {} в {}.", decryptedPath, encryptedPath);
                ensureParentExists(encryptedPath);
                Path encryptedTemp = encryptedPath.resolveSibling(encryptedPath.getFileName().toString() + ".tmp");
                try {
                    transformFile(decryptedPath, encryptedTemp, Cipher.ENCRYPT_MODE);
                    moveWithRetry(encryptedTemp, encryptedPath);
                } finally {
                    wipeAndDelete(encryptedTemp);
                }
                wipeAndDelete(decryptedPath);
            } catch (IOException | GeneralSecurityException e) {
                LOGGER.error("Не удалось зашифровать базу данных при завершении работы.", e);
            }
        }
    }

    // Флаг, который указывает, была ли база создана на этом запуске.
    // Возвращает true ровно один раз после создания.
    public boolean consumeDatabaseJustCreatedFlag() {
        return databaseJustCreated.getAndSet(false);
    }
    // Метод для шифрования и расшифрования файла с использованием DES в режиме OFB
    private void transformFile(Path source, Path target, int cipherMode) throws GeneralSecurityException, IOException {
        Cipher cipher = Cipher.getInstance("DES/OFB/NoPadding");
        SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(cipherMode, keySpec, ivSpec);

        ensureParentExists(target);

        try (InputStream input = Files.newInputStream(source);
             OutputStream output = Files.newOutputStream(target, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
             CipherOutputStream cipherOut = new CipherOutputStream(output, cipher)) {

            byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) != -1) {
                cipherOut.write(buffer, 0, read);
            }
        }
    }
    //
    // Метод для безопасного удаления файла с перезаписью его содержимого нулями
    private void wipeAndDelete(Path path) throws IOException {
        if (path == null || !Files.exists(path)) {
            return;
        }

        final int maxAttempts = 40;
        IOException lastException = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                overwriteWithZeros(path);
                Files.deleteIfExists(path);
                return;
            } catch (IOException e) {
                lastException = e;
                if (attempt == maxAttempts) {
                    break;
                }
                LOGGER.debug("Не удалось удалить файл {} (попытка {} из {}). {}", path, attempt, maxAttempts, e.getMessage());
                try {
                    long delay = 250L * attempt;
                    Thread.sleep(Math.min(delay, 2000L)); // не наращиваем задержку бесконечно
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Удаление файла " + path + " прервано.", interrupted);
                }
            }
        }

        throw lastException != null ? lastException : new IOException("Не удалось удалить файл " + path);
    }

    // Метод для перезаписи файла нулями перед удалением
    private void overwriteWithZeros(Path path) {
        if (!Files.isRegularFile(path)) {
            return;
        }
        try (RandomAccessFile raf = new RandomAccessFile(path.toFile(), "rws")) {
            byte[] zeros = new byte[4096];
            long remaining = raf.length();
            while (remaining > 0) {
                int chunk = (int) Math.min(zeros.length, remaining);
                raf.write(zeros, 0, chunk);
                remaining -= chunk;
            }
            raf.getFD().sync();
        } catch (IOException e) {
            LOGGER.warn("Не удалось перезаписать файл {} перед удалением.", path, e);
        }
    }

    // Переводим ключи и IV из шестнадцатеричного представления в байты,
    // так как DES ожидает байтовый массив длиной 8 байт (16 шестнадцатеричных символов),
    // а конфигурация обычно задаётся в текстовом виде.
    private byte[] decodeHex(String propertyName, String hex) {
        if (hex == null) {
            throw new IllegalStateException("Не задан параметр " + propertyName + ". Установите переменную окружения.");
        }
        String normalized = hex.replaceAll("\\s", "");
        if (normalized.length() != 16) {
            throw new IllegalStateException("Параметр " + propertyName + " должен содержать 16 шестнадцатеричных символов (8 байт).");
        }
        byte[] result = new byte[8];
        for (int i = 0; i < result.length; i++) {
            int index = i * 2;
            try {
                result[i] = (byte) Integer.parseInt(normalized.substring(index, index + 2), 16);
            } catch (NumberFormatException ex) {
                throw new IllegalStateException("Параметр " + propertyName + " должен быть в шестнадцатеричном виде.", ex);
            }
        }
        return result;
    }
    //Проверяем и создаём родительские директории для пути, если их нет
    private void ensureParentExists(Path path) throws IOException {
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
    }
    // Нормализуем путь, делая его абсолютным, если он относительный
    private Path resolvePath(String rawPath) {
        Path path = Paths.get(rawPath);
        if (!path.isAbsolute()) {
            path = path.toAbsolutePath();
        }
        return path.normalize();
    }

    // Создаём временный файл-сосед с заданным суффиксом
    private Path createTempSibling(Path original, String suffix) {
        String fileName = original.getFileName().toString();
        return original.resolveSibling(fileName + suffix);
    }

    // Метод для перемещения файла с повторными попытками в случае неудачи
    private void moveWithRetry(Path source, Path target) throws IOException {
        final int maxAttempts = 40;
        IOException lastException = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                tryMove(source, target);
                return;
            } catch (IOException e) {
                lastException = e;
                if (attempt == maxAttempts) {
                    break;
                }
                LOGGER.debug("Не удалось переместить {} в {} (попытка {} из {}). {}", source, target, attempt, maxAttempts, e.getMessage());
                try {
                    long delay = 250L * attempt;
                    Thread.sleep(Math.min(delay, 2000L));
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Перемещение " + source + " в " + target + " прервано.", interrupted);
                }
            }
        }
        throw lastException != null ? lastException : new IOException("Не удалось переместить " + source + " в " + target);
    }

    private void tryMove(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException ex) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

}
