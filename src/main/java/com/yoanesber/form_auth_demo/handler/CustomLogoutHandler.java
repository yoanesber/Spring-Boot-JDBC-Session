package com.yoanesber.form_auth_demo.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class CustomLogoutHandler implements LogoutSuccessHandler {

    @Value("${logout-success-url}")
    private String logoutSuccessUrl;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, 
        HttpServletResponse response, 
        Authentication authentication) throws IOException {

        // Redirect to a custom URL after logout
        response.sendRedirect(logoutSuccessUrl);
    }
}