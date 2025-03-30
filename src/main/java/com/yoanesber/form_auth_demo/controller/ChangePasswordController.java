package com.yoanesber.form_auth_demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.yoanesber.form_auth_demo.dto.ChangePasswordDTO;
import com.yoanesber.form_auth_demo.entity.CustomUserDetails;
import com.yoanesber.form_auth_demo.entity.User;
import com.yoanesber.form_auth_demo.service.ChangePasswordService;
import com.yoanesber.form_auth_demo.service.HelperService;


@Controller
public class ChangePasswordController {

    private final HelperService helperService;
    private final ChangePasswordService changePasswordService;

    private static final String SUCCESS_MESSAGE = "Password changed successfully. Please login again.";

    @Value("${logout-url}")
    private String logoutUrl;

    public ChangePasswordController(ChangePasswordService changePasswordService, 
        HelperService helperService) {
        this.changePasswordService = changePasswordService;
        this.helperService = helperService;
    }

    @GetMapping("/force-change-password")
    public String forceChange(HttpServletRequest request, @ModelAttribute ChangePasswordDTO changePasswordObj, Model model) {
        try {
            // Get principal from session
            CustomUserDetails userSession = helperService.getPrincipalFromSession(request.getSession(false));

            if ( userSession == null) {
                // If user session is null, force logout
                return "redirect:" + logoutUrl;
            }
            
            // Set attributes for the model
            model.addAttribute("fullName", (userSession.getFirstName() + " " + userSession.getLastName()).trim());
            model.addAttribute("changePasswordObj", (changePasswordObj != null) ? changePasswordObj : new ChangePasswordDTO());

            return "ForceChangePasswordPage";
        } catch (Exception e) {
            // If any exception occurs, force logout
            return "redirect:" + logoutUrl;
        }
    }

    @PostMapping("/force-change-password")
    public String forceChangeAction(HttpServletRequest request, 
    @ModelAttribute ChangePasswordDTO changePasswordObj, RedirectAttributes redirectAttributes, Model model) {
        // Get principal from session
        final HttpSession session = request.getSession(false);
        CustomUserDetails userSession = helperService.getPrincipalFromSession(session);
            
        // Get user id from session
        Long userId = userSession.getId();

        try {
            // Change password & last login using the ChangePasswordService
            User updatedUser = changePasswordService.forceChange(changePasswordObj.getPassword(), changePasswordObj.getConfirmPassword(), userId);

            // set the last login time in the session
            session.setAttribute("lastLogin", updatedUser.getLastLogin());

            // Set some attributes to be displayed on the page
            model.addAttribute("fullName", (userSession.getFirstName() + " " + userSession.getLastName()).trim());
            model.addAttribute("changePasswordObj", new ChangePasswordDTO());
            model.addAttribute("successMessage", SUCCESS_MESSAGE);
            return "ForceChangePasswordPage";
        } catch (Exception e) {
            // Set some attributes to be displayed on the page
            model.addAttribute("fullName", (userSession.getFirstName() + " " + userSession.getLastName()).trim());
            model.addAttribute("changePasswordObj", changePasswordObj);
            model.addAttribute("errorMessage", e.getMessage());
            return "ForceChangePasswordPage";
        }
    }
}
