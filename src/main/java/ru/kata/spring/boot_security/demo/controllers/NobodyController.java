package ru.kata.spring.boot_security.demo.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.services.UserServiceImpl;

import java.security.Principal;

@Controller
@RequestMapping("/nobody")
public class NobodyController {
    private final UserServiceImpl userService;

    @Autowired
    public NobodyController(UserServiceImpl userService) {
        this.userService = userService;
    }

    @GetMapping()
    public String getNobody(Principal principal, Model model) {
        model.addAttribute("user", userService.findByUsername(principal.getName()));
        return "nobody/nobody";
    }
}
