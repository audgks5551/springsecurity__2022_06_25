package com.example.springsecurity.example1.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(@RequestParam(value = "success", required = false) String success,
                       @RequestParam(value = "message", required = false) String message,
                       Model model) {

        model.addAttribute("success", success);
        model.addAttribute("successMessage", message);
        return "home";
    }
}
