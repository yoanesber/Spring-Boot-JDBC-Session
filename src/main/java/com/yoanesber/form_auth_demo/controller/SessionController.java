package com.yoanesber.form_auth_demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;
import com.yoanesber.form_auth_demo.service.HelperService;
import com.yoanesber.form_auth_demo.service.SessionService;

@Controller
public class SessionController {

    private final HelperService helperService;

    private final SessionService sessionService;

    @Value("${error-403-url}")
    private String error403Url;

    @Value("${error-500-url}")
    private String error500Url;

    public SessionController(HelperService helperService,
        SessionService sessionService) {
        this.helperService = helperService;
        this.sessionService = sessionService;
    }

    @GetMapping("/admin/active-sessions")
    public String activeSessions(HttpServletRequest request, Model model) {
        try {
            // Get principal from session
            CustomUserDetails userSession = sessionService.getPrincipalFromSession(request.getSession(false));

            if (userSession == null) {
                // If user session is null, redirect to forbidden page
                return "redirect:" + error403Url;
            }

            // Set attributes for the model
            model.addAttribute("fullName", (userSession.getFirstName() + " " + userSession.getLastName()).trim());

            // Check if the user has admin role
            Boolean hasRoleAdmin = helperService.hasRoleAdmin(userSession);
            if (hasRoleAdmin) {
                model.addAttribute("hasRoleAdmin", true);
            } else {
                model.addAttribute("hasRoleUser", true);
            }

            // Get all active sessions
            model.addAttribute("sessionInfoMap", sessionService.getAllActiveSessions());

            return "ActiveSessionsPage";
        } catch (Exception e) {
            // If any exception occurs, redirect to error page
            return "redirect:" + error500Url;
        }
    }

    @PostMapping("/admin/invalidate-session")
    public String invalidateSession(HttpServletRequest request, Model model) {
        try {
            // Get principal from session
            CustomUserDetails userSession = sessionService.getPrincipalFromSession(request.getSession(false));
            if (userSession == null) {
                // If user session is null, redirect to forbidden page
                return "redirect:" + error403Url;
            }

            // Get session ID from request parameter
            String sessionId = request.getParameter("sessionId");
            if (sessionId == null || sessionId.isBlank()) {
                // If session ID is null or blank, redirect to error page
                return "redirect:" + error500Url;
            }

            try {
                // Invalidate the session
                sessionService.invalidateSession(sessionId);
            } catch (Exception e) {
                // If any exception occurs, redirect to error page
                return "redirect:" + error500Url;
            }

            return "redirect:/admin/active-sessions";
        } catch (Exception e) {
            // If any exception occurs, redirect to error page
            return "redirect:" + error500Url;
        }
    }
}
