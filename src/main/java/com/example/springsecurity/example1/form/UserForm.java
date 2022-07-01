package com.example.springsecurity.example1.form;

import lombok.Data;

@Data
public class UserForm {
    private String username;
    private String password;
    private String email;
    private String age;
}
