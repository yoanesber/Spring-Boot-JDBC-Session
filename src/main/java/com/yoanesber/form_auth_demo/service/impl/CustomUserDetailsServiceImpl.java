package com.yoanesber.form_auth_demo.service.impl;

import org.hibernate.Hibernate;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;
import com.yoanesber.form_auth_demo.entity.User;
import com.yoanesber.form_auth_demo.repository.UserRepository;
import com.yoanesber.form_auth_demo.service.CustomUserDetailsService;

@Service
public class CustomUserDetailsServiceImpl implements CustomUserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String userName) {
        Assert.notNull(userName, "Username must not be null");
        
        // Find a user by its username
        User user = userRepository.findByUserName(userName).orElse(null);

        if (user != null) {
            // Initialize the lazy-loaded roles collection
            Hibernate.initialize(user.getUserRoles());

            // Build the custom user details from the user as the principal
            return CustomUserDetails.build(user);
        } else {
            // Throw an exception
            throw new UsernameNotFoundException("User not found with username: " + userName);
        }
    }
}