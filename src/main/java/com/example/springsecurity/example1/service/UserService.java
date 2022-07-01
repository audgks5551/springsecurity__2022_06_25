package com.example.springsecurity.example1.service;

import com.example.springsecurity.example1.domain.AccountDto;

public interface UserService {
    void createUser(AccountDto accountDto);
}
