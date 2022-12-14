package com.example.userservice.repository;

import com.example.userservice.domain.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository  extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
