package com.yoanesber.form_auth_demo.service.impl;

import java.time.Instant;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import com.yoanesber.form_auth_demo.entity.User;
import com.yoanesber.form_auth_demo.repository.UserRepository;
import com.yoanesber.form_auth_demo.service.UserService;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    public UserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public User findByUserName(String userName) {
        Assert.hasText(userName, "The userName cannot be null");

        // Find the user by its username
        return userRepository.findByUserName(userName).orElse(null);
    }

    @Override
    public User findByUserId(Long userId) {
        Assert.notNull(userId, "The userId cannot be null");

        // Find the user by its id
        return userRepository.findById(userId).orElse(null);
    }

    @Override
    @Transactional
    public User updateLastLogin(String userName) throws Exception {
        Assert.hasText(userName, "The userName cannot be null");

        // Find the user by its username
        User user = userRepository.findByUserName(userName).orElse(null);

        // If the user exists, update the last login
        if (user != null) {
            user.setLastLogin(Instant.now());
            user.setUpdatedBy("System");
            user.setUpdatedDate(Instant.now());
            return userRepository.save(user);
        } else {
            throw new Exception("User not found");
        }
    }
    
    @Override
    @Transactional
    public void lockAccount(String userName) throws Exception {
        Assert.hasText(userName, "The userName cannot be null");

        // Find the user by its username
        User user = userRepository.findByUserName(userName).orElse(null);

        // If the user exists, lock the account
        if (user != null) {
            user.setAccountNonLocked(false);
            user.setUpdatedBy("System");
            user.setUpdatedDate(Instant.now());
            userRepository.save(user);
        } else {
            throw new Exception("User not found");
        }
    }

    @Override
    @Transactional
    public void setAccountToExpire(String userName) throws Exception {
        Assert.hasText(userName, "The userName cannot be null");

        // Find the user by its username
        User user = userRepository.findByUserName(userName).orElse(null);

        // If the user exists, set the account to expire
        if (user != null) {
            user.setAccountNonExpired(false);
            user.setUpdatedBy("System");
            user.setUpdatedDate(Instant.now());
            userRepository.save(user);
        } else {
            throw new Exception("User not found");
        }
    }

    @Override
    @Transactional
    public void setCredentialsToExpire(String userName) throws Exception {
        Assert.hasText(userName, "The userName cannot be null");

        // Find the user by its username
        User user = userRepository.findByUserName(userName).orElse(null);

        // If the user exists, set the credentials to expire
        if (user != null) {
            user.setCredentialsNonExpired(false);
            user.setUpdatedBy("System");
            user.setUpdatedDate(Instant.now());
            userRepository.save(user);
        } else {
            throw new Exception("User not found");
        }
    }
}
