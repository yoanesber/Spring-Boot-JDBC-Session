package com.yoanesber.form_auth_demo.service.impl;

import java.time.Instant;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import com.yoanesber.form_auth_demo.entity.User;
import com.yoanesber.form_auth_demo.repository.UserRepository;
import com.yoanesber.form_auth_demo.service.ChangePasswordService;
import com.yoanesber.form_auth_demo.service.PasswordEncoderService;
import com.yoanesber.form_auth_demo.service.UserService;

@Service
public class ChangePasswordServiceImpl implements ChangePasswordService {

    private final PasswordEncoderService passwordEncoderService;
    private final UserRepository userRepository;
    private final UserService userService;

    public ChangePasswordServiceImpl(PasswordEncoderService passwordEncoderService, 
        UserRepository userRepository, UserService userService) {
        this.passwordEncoderService = passwordEncoderService;
        this.userRepository = userRepository;
        this.userService = userService;
    }

    @Override
    @Transactional
    public User forceChange(String newPassword, String confirmPassword, Long userId) throws Exception {
        Assert.notNull(userId, "The userId cannot be null");
        Assert.hasText(newPassword, "The newPassword cannot be null");
        Assert.hasText(confirmPassword, "The confirmPassword cannot be null");

        // Check if the new password and confirm password match
        if (!newPassword.equals(confirmPassword)) {
            throw new Exception("New password and confirm password do not match");
        }

        // Find the user by its id
        User existingUser = userService.findByUserId(userId);
        if (existingUser == null) {
            throw new Exception("User not found");
        }

        // Add some validation for the new password (e.g., length, complexity)
        // Can use fluent validation or custom validation logic here, see this repo: https://github.com/yoanesber/Spring-Boot-Validation-Using-Java-Fluent-Validator

        // Update the user's password and last login date
        existingUser.setPassword(passwordEncoderService.encode(newPassword));
        existingUser.setLastLogin(Instant.now());
        existingUser.setUpdatedBy("System");
        existingUser.setUpdatedDate(Instant.now());

        // Save the updated user to the database
        return userRepository.save(existingUser);
    }
}
