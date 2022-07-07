package com.example.springsecurity.example1.controller.user;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

    @GetMapping("/message")
    public String message(@RequestParam(value = "success", required = false) String success,
                          @RequestParam(value = "message", required = false) String message,
                          Model model) {

        model.addAttribute("success", success);
        model.addAttribute("successMessage", message);
        return "user/message";
    }

    @GetMapping("/api/messages")
    @ResponseBody
    public String apiMessage() {
        return "messages_ok";
    }
}
