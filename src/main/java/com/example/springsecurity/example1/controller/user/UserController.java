package com.example.springsecurity.example1.controller.user;

import com.example.springsecurity.example1.domain.Account;
import com.example.springsecurity.example1.domain.AccountDto;
import com.example.springsecurity.example1.form.LoginForm;
import com.example.springsecurity.example1.form.SignUpForm;
import com.example.springsecurity.example1.security.token.AjaxAuthenticationToken;
import com.example.springsecurity.example1.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;

@Controller
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("/myPage")
    public String myPage(@RequestParam(value = "success", required = false) String success,
                         @RequestParam(value = "message", required = false) String message,
                         Model model) {

        model.addAttribute("success", success);
        model.addAttribute("successMessage", message);
        return "user/myPage";
    }

    @GetMapping("/users")
    public String createUserForm(SignUpForm signUpForm) {
        return "user/login/register";
    }

    @PostMapping("/users")
    public String createUser(SignUpForm signUpForm) {

        ModelMapper mapper = new ModelMapper();
        AccountDto accountDto = mapper.map(signUpForm, AccountDto.class);

        userService.createUser(accountDto);

        return "redirect:/login";
    }

    @GetMapping("/login")
    public String loginForm(
            @RequestParam(value = "exception", required = false) String exception,
            @RequestParam(value = "error", required = false) String error,
            LoginForm loginForm,
            Model model
    ) {
        model.addAttribute("error", error);
        model.addAttribute("errorMessage", exception);

        return "user/login/login";
    }

    @GetMapping("/api/login")
    public String ajaxLoginForm(
            @RequestParam(value = "exception", required = false) String exception,
            @RequestParam(value = "error", required = false) String error,
            LoginForm loginForm,
            Model model
    ) {
        model.addAttribute("error", error);
        model.addAttribute("errorMessage", exception);

        return "user/login/ajax_login";
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        return "redirect:/login";
    }

    @GetMapping({"/denied", "/api/denied"})
    public String accessDenied(@RequestParam(value = "exception", required = false) String exception, Model model, Principal principal) {

        Account account = null;

        if (principal instanceof UsernamePasswordAuthenticationToken) {
            account = (Account) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();

        } else if (principal instanceof AjaxAuthenticationToken) {
            account = (Account) ((AjaxAuthenticationToken) principal).getPrincipal();
        }

        model.addAttribute("username", account.getUsername());
        model.addAttribute("exception", exception);

        return "user/login/denied";
    }
}
