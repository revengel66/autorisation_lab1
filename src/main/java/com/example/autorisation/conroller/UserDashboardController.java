package com.example.autorisation.conroller;

import com.example.autorisation.entity.User;
import com.example.autorisation.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Objects;

@Controller
@RequestMapping("/user")
public class UserDashboardController {
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    public UserDashboardController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping
    public String home(@AuthenticationPrincipal User currentUser, Model model) {
        model.addAttribute("user", currentUser);
        return "user-form";
    }

    @PostMapping("/password")
    public String changePassword(@AuthenticationPrincipal User currentUser,
                                 @RequestParam("password") String password,
                                 @RequestParam("confirmPassword") String confirmPassword,
                                 @RequestParam("currentPassword") String currentPassword,
                                 RedirectAttributes redirectAttributes) {

        if (!passwordEncoder.matches(currentPassword, currentUser.getPassword())) {
            redirectAttributes.addFlashAttribute("error", "Старый пароль введен неверно");
            return "redirect:/user";
        }
        else if (password == null || password.isBlank()) {
            redirectAttributes.addFlashAttribute("error", "Пароль не может быть пустым");
            return "redirect:/user";
        }
        else if (currentUser.isRestriction() && password.length() < currentUser.getLength()) {
            redirectAttributes.addFlashAttribute("error",
                    "Пароль должен содержать не менее " + currentUser.getLength() + " символов");
            return "redirect:/user";
        }
        else if (currentUser.isRestriction() && !Restriction(password)) {
            redirectAttributes.addFlashAttribute("error",
                    "Пароль должен содержать чередование цифр и знаков арифметических операций");
            return "redirect:/user";
        }
        else if (!Objects.equals(password, confirmPassword)) {
            redirectAttributes.addFlashAttribute("error", "Пароли не совпадают");
            return "redirect:/user";
        }
        userService.updatePassword(currentUser.getId(), password);
        redirectAttributes.addFlashAttribute("message", "Пароль успешно обновлен");
        return "redirect:/user";
    }
//    1+2/3*4
//    1+2...3*4
    private boolean Restriction(String password) {
        char[] chars = password.toCharArray();
        boolean flag = false;
        for (int i = 0; i < chars.length - 1; i++) {
            if (Character.isDigit(chars[i])) {
                if (isArithmeticSymbol(chars[i + 1])) {
                    flag = true;
                    continue;
                }
                else {
                    return false;
                }
            } else if (isArithmeticSymbol(chars[i])) {
                if (Character.isDigit(chars[i + 1])) {
                    flag = true;
                    continue;
                }
                else {
                    return false;
                }
            }
        }
        return flag;
    }

    private boolean isArithmeticSymbol(char c) {
        if( c == '+' || c == '-' || c == '*' || c == '/' || c == '%') {;
            return true;
        }
        return false;
    }
}
