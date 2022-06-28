package com.example.springsecurity.example1.controller.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UserController {

    @GetMapping("/myPage")
    public String myPage() {
        return "user/myPage";
    }
}
