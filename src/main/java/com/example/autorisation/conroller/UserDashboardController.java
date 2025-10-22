package com.example.autorisation.conroller;

import com.example.autorisation.entity.User;
import com.example.autorisation.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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

    private final UserService userService;

    public UserDashboardController(UserService userService) {
        this.userService = userService;
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
                                 RedirectAttributes redirectAttributes) {
        if (!Objects.equals(password, confirmPassword)) {
            redirectAttributes.addFlashAttribute("error", "Пароли не совпадают");
            return "redirect:/user";
        }
        if (password == null || password.isBlank()) {
            redirectAttributes.addFlashAttribute("error", "Пароль не может быть пустым");
            return "redirect:/user";
        }
        if (currentUser.isRestriction() && password.length() < currentUser.getLength()) {
            redirectAttributes.addFlashAttribute("error",
                    "Пароль должен содержать не менее " + currentUser.getLength() + " символов");
            return "redirect:/user";
        }
        userService.updatePassword(currentUser.getId(), password);
        redirectAttributes.addFlashAttribute("message", "Пароль успешно обновлен");
        return "redirect:/user";
    }
}
