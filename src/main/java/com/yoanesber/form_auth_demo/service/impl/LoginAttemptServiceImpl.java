package com.yoanesber.form_auth_demo.service.impl;

import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import com.yoanesber.form_auth_demo.service.LoginAttemptService;
import com.yoanesber.form_auth_demo.service.UserService;

@Service
public class LoginAttemptServiceImpl implements LoginAttemptService {
    private final UserService userService;

    @Value("${max-attempt-login}")
    private int MAX_ATTEMPT;
    
    private Map<String, Integer> attemptsCache = new HashMap<>();

    public LoginAttemptServiceImpl(UserService userService) {
        this.userService = userService;
    }

    @Override
    public void loginFailed(String userName) throws Exception {
        Assert.hasText(userName, "The userName cannot be null");

        try {
            // Increment the number of attempts
            int attempts = attemptsCache.getOrDefault(userName, 0);
            attempts++;

            // Put the new number of attempts in the cache
            attemptsCache.put(userName, attempts);

            // If the number of attempts is greater than or equal to the maximum number of attempts, lock the account
            if (attempts >= MAX_ATTEMPT) {
                userService.lockAccount(userName);
            }
        } catch (Exception e) {
            throw new Exception(e.getMessage());
        }
    }

    @Override
    public void loginSucceeded(String userName) {
        Assert.hasText(userName, "The userName cannot be null");
        attemptsCache.remove(userName);
    }
}