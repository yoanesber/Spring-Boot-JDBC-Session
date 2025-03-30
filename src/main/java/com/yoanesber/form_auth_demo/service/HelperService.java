package com.yoanesber.form_auth_demo.service;

import jakarta.servlet.http.HttpSession;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;

public interface HelperService {
    // Check if the user has the role ADMIN
    Boolean hasRoleAdmin(CustomUserDetails userSession);

    // Check if the user has the role USER
    Boolean hasRoleUser(CustomUserDetails userSession);

    // Get the principal from the session
    CustomUserDetails getPrincipalFromSession(HttpSession session);

    // Clear the authentication attributes from the session
    void clearSessionAttributes(HttpSession session);
}
