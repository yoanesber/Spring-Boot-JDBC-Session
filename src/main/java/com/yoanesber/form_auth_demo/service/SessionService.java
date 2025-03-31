package com.yoanesber.form_auth_demo.service;

import jakarta.servlet.http.HttpSession;
import java.util.List;
import org.springframework.security.core.session.SessionInformation;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;

public interface SessionService {

    // Get all active users
    List<SessionInformation> getAllActiveUsers();

    // Get all active users by username
    List<SessionInformation> getAllActiveUsers(String username);

    // Get the principal from the session
    CustomUserDetails getPrincipalFromSession(HttpSession session);

    // Set the maximum inactive interval for a session  
    void setMaxInactiveInterval(int interval, HttpSession session);

    // Invalidate a session by ID
    void invalidateSession(String sessionId);

    // Invalidate all sessions for a user
    void invalidateOtherSessions(String username, String sessionId);

    // Invalidate all sessions for all users
    void invalidateAllSessions();

    // Set a session attribute
    void setSessionAttribute(String key, Object value, HttpSession session);

    // Get a session attribute by key
    Object getSessionAttribute(String key, HttpSession session);

    // Remove a session attribute by key
    void removeSessionAttribute(String key, HttpSession session);

    // Clear all session attributes
    void clearSession(HttpSession session);

}
