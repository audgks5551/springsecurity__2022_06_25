package com.example.springsecurity.example1.service;

import com.example.springsecurity.example1.domain.Account;
import com.example.springsecurity.example1.domain.AccountDto;
import com.example.springsecurity.example1.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;

    @Transactional
    @Override
    public void createUser(AccountDto accountDto) {

        ModelMapper mapper = new ModelMapper();
        Account account = mapper.map(accountDto, Account.class);

        account.setPassword(encoder.encode(account.getPassword()));
        account.setRole("ROLE_USER");

        userRepository.save(account);
    }
}
