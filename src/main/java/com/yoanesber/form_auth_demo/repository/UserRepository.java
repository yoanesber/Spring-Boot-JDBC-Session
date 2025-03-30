package com.yoanesber.form_auth_demo.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.yoanesber.form_auth_demo.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    // Find a user by its username
    Optional<User> findByUserName(String userName);

    // Check if a user exists by its username
    Boolean existsByUserName(String userName);

    // Check if a user exists by its email
    Boolean existsByEmail(String email);
}
