package com.yoanesber.form_auth_demo.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.stream.Collectors;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.WebAttributes;
import org.springframework.stereotype.Component;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;
import com.yoanesber.form_auth_demo.service.LoginAttemptService;
import com.yoanesber.form_auth_demo.service.SessionService;

@Component
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private SessionService sessionService;

    private static final int MAX_INACTIVE_INTERVAL = 60 * 60; // 1 hour

    @Value("${login-success-url}")
    private String loginSuccessUrl;

    @Value("${error-403-url}")
    private String error403Url;

    @Value("${error-500-url}")
    private String error500Url;

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

                // Manually invalidate all sessions for the user
                // This is to ensure that the user is logged out from all other sessions
                sessionService.invalidateOtherSessions(userName, session.getId());

                // Set session inactive interval
                sessionService.setMaxInactiveInterval(MAX_INACTIVE_INTERVAL, session);
                
                // Set session attributes
                sessionService.setSessionAttribute("userName", userName, session);
                sessionService.setSessionAttribute("userRole", this.getUserRole(authentication), session);
                sessionService.setSessionAttribute("ipAddress", this.getIpAddress(request), session);

                Instant lastLogin = this.getLastLogin(authentication);
                if (lastLogin != null) {
                    sessionService.setSessionAttribute("lastLogin", lastLogin, session);
                } 
                
                // Remove the login attempt from the cache
                loginAttemptService.loginSucceeded(userName);

                // Clear the authentication attributes if any
                clearAuthenticationAttributes(request);

                // Redirect to the login success URL
                response.sendRedirect(loginSuccessUrl);
                return;
            } else {
                // If session is null, redirect to forbidden page
                response.sendRedirect(error403Url);
                return;
            }
        } catch (Exception e) {
            // Redirect to the error page if any exception occurs
            response.sendRedirect(error500Url);
            return;
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
        sessionService.removeSessionAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, session);
    }
}