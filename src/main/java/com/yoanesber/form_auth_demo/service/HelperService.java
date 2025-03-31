package com.yoanesber.form_auth_demo.service;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;

public interface HelperService {
    // Check if the user has the role ADMIN
    Boolean hasRoleAdmin(CustomUserDetails userSession);

    // Check if the user has the role USER
    Boolean hasRoleUser(CustomUserDetails userSession);
}
