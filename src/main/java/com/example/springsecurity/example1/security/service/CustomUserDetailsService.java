package com.example.springsecurity.example1.security.service;

import com.example.springsecurity.example1.domain.Account;
import com.example.springsecurity.example1.repository.UserRepository;
import com.example.springsecurity.example1.security.entity.AccountContext;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;

/**
 * spring security service
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("UsernameNotFoundException"));

        return new AccountContext(account, Arrays.asList(new SimpleGrantedAuthority(account.getRole())));
    }
}
