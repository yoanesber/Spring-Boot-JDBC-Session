package com.yoanesber.form_auth_demo.service.impl;

import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Service;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;
import com.yoanesber.form_auth_demo.service.HelperService;

@Service
public class HelperServiceImpl implements HelperService {

    @Override
    public CustomUserDetails getPrincipalFromSession(HttpSession session) {
        final SecurityContextImpl sci = (SecurityContextImpl) session.getAttribute("SPRING_SECURITY_CONTEXT");

        if (sci != null) 
            return (CustomUserDetails) sci.getAuthentication().getPrincipal();

        return null;
    }

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

    @Override
    public void clearSessionAttributes(HttpSession session) {
        if (session != null) {
            session.removeAttribute("userName");
            session.removeAttribute("userRole");
            session.removeAttribute("ipAddress");
        }
    }
}
