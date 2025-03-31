package com.yoanesber.form_auth_demo.service.impl;

import org.springframework.stereotype.Service;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;
import com.yoanesber.form_auth_demo.service.HelperService;

@Service
public class HelperServiceImpl implements HelperService {

    @Override
    public Boolean hasRoleAdmin(CustomUserDetails userSession) {
        return userSession.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
    }

    @Override
    public Boolean hasRoleUser(CustomUserDetails userSession) {
        return userSession.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_USER"));
    }
}
