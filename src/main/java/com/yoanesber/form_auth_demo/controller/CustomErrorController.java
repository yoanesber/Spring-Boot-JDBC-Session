package com.yoanesber.form_auth_demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.RequestDispatcher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;
import com.yoanesber.form_auth_demo.service.HelperService;

@Controller
public class CustomErrorController implements ErrorController {

    private final HelperService helperService;

    @Value("${error-page-403}")
    private String errorPage403;

    @Value("${error-page-404}")
    private String errorPage404;

    @Value("${error-page-415}")
    private String errorPage415;

    @Value("${error-page-500}")
    private String errorPage500;

    public CustomErrorController(HelperService helperService) {
        this.helperService = helperService;
    }

    // to display error page according to error status code
    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        // Get principal from session
        CustomUserDetails userSession = helperService.getPrincipalFromSession(request.getSession(false));

        // Set some attributes
        model.addAttribute("fullName", (userSession.getFirstName() + " " + userSession.getLastName()).trim());

        // Get the error status code
        String status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE).toString();

        if (status != null && !status.isBlank()) {
            Integer statusCode = Integer.valueOf(status);

            if (statusCode == HttpStatus.FORBIDDEN.value())
                return errorPage403;
            else if (statusCode == HttpStatus.NOT_FOUND.value())
                return errorPage404;
            else if (statusCode == HttpStatus.UNSUPPORTED_MEDIA_TYPE.value())
                return errorPage415;
            else return errorPage500;
        }

        return errorPage500;
    }

    // to display http error 403
    @RequestMapping("/error/403")
    public String handleError403(HttpServletRequest request, Model model) {
        // Get principal from session
        CustomUserDetails userSession = helperService.getPrincipalFromSession(request.getSession(false));

        // Set some attributes
        model.addAttribute("fullName", (userSession.getFirstName() + " " + userSession.getLastName()).trim());
        
        return errorPage403;
    }

    // to display http error 404
    @RequestMapping("/error/404")
    public String handleError404(HttpServletRequest request, Model model) {
        // Get principal from session
        CustomUserDetails userSession = helperService.getPrincipalFromSession(request.getSession(false));

        // Set some attributes
        model.addAttribute("fullName", (userSession.getFirstName() + " " + userSession.getLastName()).trim());
        
        return errorPage404;
    }

    // to display http error 415
    @RequestMapping("/error/415")
    public String handleError415(HttpServletRequest request, Model model) {
        // Get principal from session
        CustomUserDetails userSession = helperService.getPrincipalFromSession(request.getSession(false));

        // Set some attributes
        model.addAttribute("fullName", (userSession.getFirstName() + " " + userSession.getLastName()).trim());
        
        return errorPage415;
    }

    // to display http error 500
    @RequestMapping("/error/500")
    public String handleError500(HttpServletRequest request, Model model) {
        // Get principal from session
        CustomUserDetails userSession = helperService.getPrincipalFromSession(request.getSession(false));

        // Set some attributes
        model.addAttribute("fullName", (userSession.getFirstName() + " " + userSession.getLastName()).trim());
        
        return errorPage500;
    }
}
