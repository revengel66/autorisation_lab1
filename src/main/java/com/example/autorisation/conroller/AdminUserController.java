package com.example.autorisation.conroller;

import com.example.autorisation.entity.User;
import com.example.autorisation.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Objects;


@Controller
@RequestMapping("/admin/users")
public class AdminUserController {

    private final UserService userService;

    public AdminUserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public String index(Model model) {
        model.addAttribute("users", userService.getAllUsers());
        return "admin-form";
    }

    @GetMapping("/new")
    public String newUser(Model model) {
        model.addAttribute("user", new User());
        return "user-create-form";
    }

    @PostMapping("/save")
    public String saveUser(@ModelAttribute("user") User user) {
        userService.saveUser(user);
        return "redirect:/admin/users";
    }

    @GetMapping("/delete/{id}")
    public String deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return "redirect:/admin/users";
    }

    @GetMapping("/toggle-blocking/{id}")
    public String toggleBlockng(@PathVariable Long id) {
        User user = userService.getUserById(id);
        user.setBlocked(!user.isBlocked());
        userService.saveUser(user);
        return "redirect:/admin/users";
    }
    @GetMapping("/toggle-restriction/{id}")
    public String toggleRestriction(@PathVariable Long id) {
        User user = userService.getUserById(id);
        user.setRestriction(!user.isRestriction());
        userService.saveUser(user);
        return "redirect:/admin/users";
    }

    @GetMapping("/edit/{id}")
    public String editRestriction(@PathVariable Long id, Model model) {
        User user = userService.getUserById(id);
        model.addAttribute("user", user);
        return "user-edit-form";
    }


}
