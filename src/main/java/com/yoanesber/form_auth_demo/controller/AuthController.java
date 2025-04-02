package com.yoanesber.form_auth_demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;
import com.yoanesber.form_auth_demo.entity.User;
import com.yoanesber.form_auth_demo.service.HelperService;
import com.yoanesber.form_auth_demo.service.UserService;
import com.yoanesber.form_auth_demo.service.SessionService;

@Controller
public class AuthController {

    private final HelperService helperService;
    private final UserService userService;
    private final SessionService sessionService;

    @Value("${login-url}")
    private String loginUrl;

    @Value("${login-success-url}")
    private String loginSuccessUrl;

    @Value("${error-403-url}")
    private String error403Url;

    @Value("${error-500-url}")
    private String error500Url;

    public AuthController(HelperService helperService, 
        UserService userService, SessionService sessionService) {
        this.helperService = helperService;
        this.userService = userService;
        this.sessionService = sessionService;
    }

    // Redirect to login page
    @GetMapping("/")
    public String homePage() {
        return "redirect:" + loginUrl;
    }

    // to display login page
    @GetMapping("/login")
    public String performLogin(@RequestParam(value = "error", required = false) String error, 
        @RequestParam(value = "errorMsg", required = false) String errorMessage, 
        HttpServletRequest request,
        Model model) {

        if (error != null && !error.isBlank()) {
            model.addAttribute("loginError", true);

            if (errorMessage != null)
                model.addAttribute("errorMessage", errorMessage);
            else model.addAttribute("errorMessage", "Invalid username or password");
        } else {
            try {
                // Get principal from session
                final HttpSession session = request.getSession(false);
                CustomUserDetails userSession = sessionService.getPrincipalFromSession(session);

                if (userSession != null) {
                    // if user session is not null, redirect to dashboard page
                    return "redirect:" + loginSuccessUrl;
                } 
            } catch (Exception e) {
                // if an error occurs, redirect to error page
                return "redirect:" + error500Url;
            }
        }

        return "LoginPage";
    }

    // to display dashboard page or force change password page
    @GetMapping("/dashboard")
    public String loginSuccess(HttpServletRequest request, Model model) {

        try {
            // Get principal from session
            final HttpSession session = request.getSession(false);
            CustomUserDetails userSession = sessionService.getPrincipalFromSession(session);

            if ( userSession != null) {
                // Check if last login is not null then set the attributes
                // to be displayed on the dashboard page
                if (userSession.getLastLogin() != null) {
                    Boolean hasRoleAdmin = helperService.hasRoleAdmin(userSession);

                    model.addAttribute("lastLogin", userSession.getLastLogin());
                    model.addAttribute("fullName", (userSession.getFirstName() + " " + userSession.getLastName()).trim());
                    model.addAttribute("userName", userSession.getUsername());
                    // add some other attributes...

                    // update last login time in the database
                    User loggedInUser = userService.updateLastLogin(userSession.getUsername());

                    // set the last login time in the current session
                    sessionService.setSessionAttribute("lastLogin", loggedInUser.getLastLogin(), session);

                    if (hasRoleAdmin) {
                        model.addAttribute("hasRoleAdmin", true);
                        return "DahsboardPage";
                    } else {
                        model.addAttribute("hasRoleUser", true);
                        return "HomePage";
                    }
                } else {
                    // if last login is null, it means the user has not logged in before
                    // so make it the first login, and force the user to change the password
                    // redirect to force change password page
                    return "redirect:/force-change-password";
                }
            } else {
                // if userSession is null, redirect to forbidden page
                return "redirect:" + error403Url;
            }
        } catch (Exception e) {
            // if an error occurs, redirect to error page
            return "redirect:" + error500Url;
        }
    }
}