package com.example.autorisation.conroller;

import com.example.autorisation.entity.Admin;
import com.example.autorisation.service.AdminService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Objects;

@Controller
@RequestMapping("/admin")
public class AdminConroller {

    private final PasswordEncoder passwordEncoder;
    private final AdminService adminService;

    public AdminConroller(PasswordEncoder passwordEncoder, AdminService adminService) {
        this.passwordEncoder = passwordEncoder;
        this.adminService = adminService;
    }

    @GetMapping
    public String home(@AuthenticationPrincipal Admin currentAdmin, Model model) {
        model.addAttribute("admin", currentAdmin);
        return "admin-form";
    }
    @GetMapping("/edit")
    public String editRestriction(@AuthenticationPrincipal Admin currentAdmin,Model model) {
        model.addAttribute("admin", currentAdmin);
        return "admin-edit-pass-form";
    }
    @PostMapping("/password")
    public String changePassword(@AuthenticationPrincipal Admin currentAdmin,
                                 @RequestParam("password") String password,
                                 @RequestParam("confirmPassword") String confirmPassword,
                                 @RequestParam("currentPassword") String currentPassword,
                                 RedirectAttributes redirectAttributes) {
        if (!passwordEncoder.matches(currentPassword, currentAdmin.getPassword())) {
            redirectAttributes.addFlashAttribute("error", "Старый пароль введен неверно");
            return "redirect:/admin/edit";
        }else if (!Objects.equals(password, confirmPassword)) {
            redirectAttributes.addFlashAttribute("error", "Пароли не совпадают");
            return "redirect:/admin/edit";
        }
        else if (password == null || password.isBlank()) {
            redirectAttributes.addFlashAttribute("error", "Пароль не может быть пустым");
            return "redirect:/admin/edit";
        }

        adminService.updatePassword(currentAdmin.getId(), password);
        redirectAttributes.addFlashAttribute("message", "Пароль успешно обновлен");
        return "redirect:/admin/edit";
    }
}
