package com.yoanesber.form_auth_demo.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.RequestDispatcher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class CustomErrorController implements ErrorController {

    @Value("${error-403-page}")
    private String error403Page;

    @Value("${error-404-page}")
    private String error404Page;

    @Value("${error-415-page}")
    private String error415Page;

    @Value("${error-500-page}")
    private String error500Page;

    // to display error page according to error status code
    @RequestMapping("/error")
    public String handleError(HttpServletRequest request, Model model) {
        // Get the error status code
        String status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE).toString();

        if (status != null && !status.isBlank()) {
            Integer statusCode = Integer.valueOf(status);

            if (statusCode == HttpStatus.FORBIDDEN.value())
                return error403Page;
            else if (statusCode == HttpStatus.NOT_FOUND.value())
                return error404Page;
            else if (statusCode == HttpStatus.UNSUPPORTED_MEDIA_TYPE.value())
                return error415Page;
            else return error500Page;
        }

        return error500Page; // Default to 500 error page if status code is not found
    }

    // to display http error 403
    @RequestMapping("/error/403")
    public String handleError403(HttpServletRequest request, Model model) {

        // Add some custom attributes to the model if needed

        return error403Page;
    }

    // to display http error 404
    @RequestMapping("/error/404")
    public String handleError404(HttpServletRequest request, Model model) {

        // Add some custom attributes to the model if needed

        return error404Page;
    }

    // to display http error 415
    @RequestMapping("/error/415")
    public String handleError415(HttpServletRequest request, Model model) {

        // Add some custom attributes to the model if needed

        return error415Page;
    }

    // to display http error 500
    @RequestMapping("/error/500")
    public String handleError500(HttpServletRequest request, Model model) {

        // Add some custom attributes to the model if needed

        return error500Page;
    }
}
