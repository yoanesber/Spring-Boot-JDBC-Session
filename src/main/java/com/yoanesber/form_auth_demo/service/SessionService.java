package com.yoanesber.form_auth_demo.service;

import jakarta.servlet.http.HttpSession;
import java.util.Map;
import java.util.List;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;

public interface SessionService {

    // Get all active sessions
    List<Map<String, Object>> getAllActiveSessions();

    // Set a session attribute
    void setSessionAttribute(String attributeName, Object value, HttpSession session);

    // Get all sessions
    List<Map<String, Object>> getSessions();

    // Get session details for a specific session ID
    Map<String, Object> getSession(String sessionId);

    // Get a session attribute by attribute name and session
    Object getSessionAttribute(String attributeName, HttpSession session);

    // Get a session attribute by attribute name and specific session ID
    Object getSessionAttribute(String attributeName, String sessionId);

    // Get the principal from the session
    CustomUserDetails getPrincipalFromSession(HttpSession session);

    // Set the maximum inactive interval for a session  
    void setMaxInactiveInterval(int interval, HttpSession session);

    // Invalidate a session by ID
    void invalidateSession(String sessionId);

    // Invalidate old sessions for a user
    void invalidateOldSessions(String username, String sessionId);

    // Invalidate all sessions
    void invalidateAllSessions();

    // Remove a session attribute by attribute name and session
    void removeSessionAttribute(String attributeName, HttpSession session);

    // Clear all session attributes
    void clearSession(HttpSession session);

}
