package com.yoanesber.form_auth_demo.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomLogoutHandler implements LogoutSuccessHandler {

    @Value("${login-url}")
    private String loginUrl;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, 
        HttpServletResponse response, 
        Authentication authentication) throws IOException {

        // Clear session attributes
        this.clearSessionAttributes(request);

        // Redirect to a custom URL after logout
        response.sendRedirect(loginUrl + "?logoutSuccess=true&logoutFrom=CustomLogoutHandler");
    }

    // Clear the authentication attributes
    private void clearSessionAttributes(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session != null) {
            session.removeAttribute("userName");
            session.removeAttribute("userRole");
            session.removeAttribute("ipAddress");
        }
    }
}