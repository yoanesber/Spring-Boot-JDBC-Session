package com.yoanesber.form_auth_demo.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface CustomUserDetailsService extends UserDetailsService{
    // to load user details into authenticationProvider
    UserDetails loadUserByUsername(String userName);
}
