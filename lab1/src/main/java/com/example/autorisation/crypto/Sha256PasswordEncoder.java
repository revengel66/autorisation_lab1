package com.example.autorisation.crypto;

import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;

public class Sha256PasswordEncoder implements PasswordEncoder {
    private Sha256Hasher hasher = new Sha256Hasher();

    @Override
    public String encode(CharSequence rawPassword) {
        String password = rawPassword == null ? "" : rawPassword.toString();
        byte[] passwordByte = password.getBytes(StandardCharsets.UTF_8);
        byte[] digest = hasher.digest(passwordByte);
        return toHex(digest);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (encodedPassword == null) {
            return rawPassword == null || rawPassword.length() == 0;
        }
        String candidate = encode(rawPassword);
        return constantTimeEquals(candidate, encodedPassword);

    }

    private static boolean constantTimeEquals(String first, String second) {
        if (first == null || second == null) {
            return first == null && second == null;
        }
        if (first.length() != second.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < first.length(); i++) {
            result |= first.charAt(i) ^ second.charAt(i);
        }
        return result == 0;
    }


    private static final char[] HEX = "0123456789abcdef".toCharArray();
    private static String toHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xFF;      // переводим байт в 0..255
            hexChars[i * 2] = HEX[value >>> 4];      // старшая тетрада
            hexChars[i * 2 + 1] = HEX[value & 0x0F]; // младшая тетрада
        }
        return new String(hexChars);
    }

}
