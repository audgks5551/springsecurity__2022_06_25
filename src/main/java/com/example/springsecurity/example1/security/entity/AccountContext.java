package com.example.springsecurity.example1.security.entity;

import com.example.springsecurity.example1.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

/**
 * spring security Entity
 */
public class AccountContext extends User {

    private final Account account;

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);

        this.account = account;
    }

    public Account getAccount() {
        return account;
    }
}
