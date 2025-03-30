package com.yoanesber.form_auth_demo.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.stream.Collectors;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Component;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;
import com.yoanesber.form_auth_demo.service.LoginAttemptService;

@Component
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final LoginAttemptService loginAttemptService;
    private static final int MAX_INACTIVE_INTERVAL = 60 * 60; // 1 hour

    @Value("${login-success-url}")
    private String loginSuccessUrl;

    @Value("${logout-url}")
    private String logoutUrl;

    public CustomLoginSuccessHandler(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    // Redirect to the dashboard page after successful login
    // Set session attributes
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, 
        HttpServletResponse response, 
        Authentication authentication) throws IOException, ServletException {

        try {
            final HttpSession session = request.getSession(false);
            
            if (session != null) {
                String userName = this.getPrincipalUserName(authentication);

                // Set session inactive interval
                session.setMaxInactiveInterval(MAX_INACTIVE_INTERVAL);
                
                // Set session attributes
                session.setAttribute("userName", userName);
                session.setAttribute("userRole", this.getUserRole(authentication));
                session.setAttribute("lastLogin", this.getLastLogin(authentication));
                session.setAttribute("ipAddress", this.getIpAddress(request));

                // Remove the login attempt from the cache
                loginAttemptService.loginSucceeded(userName);
            }

            // Clear the authentication attributes if any
            clearAuthenticationAttributes(request);

            // Redirect to the login success URL
            response.sendRedirect(loginSuccessUrl);
        } catch (Exception e) {
            // Redirect to the logout URL if an error occurs
            response.sendRedirect(logoutUrl);
        }
    }

    // Get the principal username from the authentication object
    private String getPrincipalUserName(final Authentication authentication) {
        if (authentication != null) {
            if (authentication.getPrincipal() instanceof CustomUserDetails)
                return ((CustomUserDetails)authentication.getPrincipal()).getUsername();
            else return authentication.getName();
        } 

        return "";
    }

    // Get the user role from the authentication object in a comma-separated string
    private String getUserRole(final Authentication authentication) {
        if (authentication != null) {
            if (authentication.getPrincipal() instanceof CustomUserDetails) {
                return ((CustomUserDetails)authentication.getPrincipal())
                    .getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.joining(", ", "[", "]"));
            }
        }

        return "";
    }

    // Get last login from the authentication object
    private Instant getLastLogin(final Authentication authentication) {
        if (authentication != null) {
            if (authentication.getPrincipal() instanceof CustomUserDetails) {
                return ((CustomUserDetails)authentication.getPrincipal()).getLastLogin();
            }
        }

        return null;
    }

    // Get the IP address of the client
    private String getIpAddress(final HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");

        if (ipAddress == null || ipAddress.isBlank()) {
            ipAddress = request.getRemoteAddr();
        }
        
        return ipAddress;
    }

    // Clear the authentication attributes e.g. the authentication exception attribute
    private void clearAuthenticationAttributes(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);

        if (session == null) {
            return;
        }

        // Remove the authentication exception attribute
        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }
}