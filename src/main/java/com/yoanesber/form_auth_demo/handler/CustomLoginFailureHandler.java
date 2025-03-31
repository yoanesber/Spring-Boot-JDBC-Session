package com.yoanesber.form_auth_demo.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.ServletException;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import com.yoanesber.form_auth_demo.service.LoginAttemptService;
import com.yoanesber.form_auth_demo.service.UserService;

@Component
public class CustomLoginFailureHandler implements AuthenticationFailureHandler {

    @Autowired
    private UserService userService;

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Value("${login-url}")
    private String loginUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, 
        HttpServletResponse response, 
        AuthenticationException exception) throws IOException, ServletException {

        // Default error message
        String errorMessage = exception.getMessage();

        // Get the username and password from the request
        String userName = request.getParameter("username");
        String password = request.getParameter("password");

        // Check if the username and password are empty
        if (userName == null || userName.isBlank() ||
            password == null || password.isBlank()) {
            errorMessage = "Username and password are required";
        }

        try {
            if (errorMessage.equalsIgnoreCase("Bad credentials")) {
                // if the error message is Bad credentials, then increment the login attempt
                // and lock the account if the maximum attempt has been reached
                errorMessage = "Invalid username or password";
                loginAttemptService.loginFailed(userName);
            } else if (errorMessage.equalsIgnoreCase("User account has expired")) {
                userService.setAccountToExpire(userName);
            } else if (errorMessage.equalsIgnoreCase("User credentials have expired")) {
                userService.setCredentialsToExpire(userName);
            } else if (errorMessage ==  null || errorMessage.isBlank()) {
                errorMessage = "An error occurred while processing your request";
            }

            response.sendRedirect(loginUrl + "?error=true&errorMsg=" + errorMessage);
        } catch (Exception e) {
            response.sendRedirect(loginUrl + "?error=true&errorMsg=An error occurred while processing your request");
        }
    }
}