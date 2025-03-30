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

@Controller
public class AuthController {

    private final HelperService helperService;
    private final UserService userService;

    @Value("${login-url}")
    private String loginUrl;

    @Value("${logout-url}")
    private String logoutUrl;

    public AuthController(HelperService helperService, UserService userService) {
        this.helperService = helperService;
        this.userService = userService;
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
        Model model) {

        if (error != null && !error.isBlank()) {
            model.addAttribute("loginError", true);

            if (errorMessage != null)
                model.addAttribute("errorMessage", errorMessage);
            else model.addAttribute("errorMessage", "Invalid username or password");
        }

        return "LoginPage";
    }

    // to display dashboard page or force change password page
    @GetMapping("/dashboard")
    public String loginSuccess(HttpServletRequest request, Model model) {

        try {
            // Get principal from session
            final HttpSession session = request.getSession(false);
            CustomUserDetails userSession = helperService.getPrincipalFromSession(session);

            if ( userSession != null) {
                // Check if last login is not null then set the attributes
                // to be displayed on the dashboard page
                if (userSession.getLastLogin() != null) {
                    model.addAttribute("lastLogin", userSession.getLastLogin());
                    model.addAttribute("fullName", (userSession.getFirstName() + " " + userSession.getLastName()).trim());
                    model.addAttribute("userName", userSession.getUsername());
                    model.addAttribute("hasRoleAdmin", helperService.hasRoleAdmin(userSession));
                    model.addAttribute("hasRoleUser", helperService.hasRoleUser(userSession));
                    // add some other attributes...

                    // update last login time in the database
                    User loggedInUser = userService.updateLastLogin(userSession.getUsername());

                    // set the last login time in the session
                    session.setAttribute("lastLogin", loggedInUser.getLastLogin());

                    return "DahsboardPage";
                } else {
                    // if last login is null, it means the user has not logged in before
                    // so make it the first login, and force the user to change the password
                    // redirect to force change password page
                    return "redirect:/force-change-password";
                }
            } else {
                // if userSession is null, it means the user is not authenticated
                // so redirect to login page
                return "redirect:" + logoutUrl;
            }
        } catch (Exception e) {
            // if an error occurs, redirect to login page
            return "redirect:" + logoutUrl;
        }
    }
}