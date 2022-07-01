package com.example.springsecurity.example1.repository;

import com.example.springsecurity.example1.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {
}
