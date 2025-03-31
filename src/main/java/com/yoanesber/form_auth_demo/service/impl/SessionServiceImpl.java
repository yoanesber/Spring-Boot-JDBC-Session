package com.yoanesber.form_auth_demo.service.impl;

import jakarta.servlet.http.HttpSession;
import java.util.List;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;
import com.yoanesber.form_auth_demo.service.SessionService;

@Service
public class SessionServiceImpl implements SessionService {

    private final SessionRegistry sessionRegistry;

    public SessionServiceImpl(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }
    
    @Override
    public List<SessionInformation> getAllActiveUsers() {
        return sessionRegistry.getAllSessions(null, false);
    }

    @Override
    public List<SessionInformation> getAllActiveUsers(String username) {
        Assert.notNull(username, "Username must not be null");

        List<Object> principals = sessionRegistry.getAllPrincipals();
        for (Object principal : principals) {
            if (principal instanceof CustomUserDetails) {
                CustomUserDetails userDetails = (CustomUserDetails) principal;
                if (userDetails.getUsername().equals(username)) {
                    return sessionRegistry.getAllSessions(principal, false);
                }
            }
        }

        return List.of(); // Return an empty list if no sessions found for the user
    }

    @Override
    public CustomUserDetails getPrincipalFromSession(HttpSession session) {

        try {
            final SecurityContextImpl sci = (SecurityContextImpl) this.getSessionAttribute("SPRING_SECURITY_CONTEXT", session);
            if (sci != null) 
                return (CustomUserDetails) sci.getAuthentication().getPrincipal();
            else return null;
        } catch (IllegalArgumentException e) {
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void setMaxInactiveInterval(int interval, HttpSession session) {
        Assert.isTrue(interval > 0, "Interval must be greater than zero");
        Assert.notNull(session, "Session must not be null");

        session.setMaxInactiveInterval(interval);
        if (session.getMaxInactiveInterval() != interval) {
            throw new IllegalStateException("Failed to set max inactive interval for session ID: " + session.getId());
        }
    }

    @Override
    public void invalidateSession(String sessionId) {
        Assert.notNull(sessionId, "Session ID must not be null");

        SessionInformation session = sessionRegistry.getSessionInformation(sessionId);
        if (session != null) {
            session.expireNow();
        }
    }

    @Override
    public void invalidateOtherSessions(String username, String sessionId) {
        Assert.notNull(username, "Username must not be null");
        Assert.notNull(sessionId, "Session ID must not be null");
        
        List<Object> principals = sessionRegistry.getAllPrincipals();
        for (Object principal : principals) {
            if (principal instanceof CustomUserDetails) {
                CustomUserDetails userDetails = (CustomUserDetails) principal;
                if (userDetails.getUsername().equals(username)) {
                    List<SessionInformation> sessions = sessionRegistry.getAllSessions(principal, false);
                    
                    // Invalidate all sessions for the user except the current session
                    for (SessionInformation session : sessions) {
                        if (session.getSessionId().equals(sessionId)) {
                            continue; // Skip the current session
                        }

                        session.expireNow();
                    }
                }
            }
        }
    }

    @Override
    public void invalidateAllSessions() {
        List<SessionInformation> sessions = sessionRegistry.getAllSessions(null, false);
        for (SessionInformation session : sessions) {
            session.expireNow();
        }
    }

    @Override
    public void setSessionAttribute(String key, Object value, HttpSession session) {
        Assert.notNull(key, "Key must not be null");
        Assert.notNull(value, "Value must not be null");
        Assert.notNull(session, "Session must not be null");

        session.setAttribute(key, value);
    }

    @Override
    public Object getSessionAttribute(String key, HttpSession session) {
        Assert.notNull(key, "Key must not be null");
        Assert.notNull(session, "Session must not be null");

        Object value = session.getAttribute(key);
        if (value == null) {
            throw new IllegalArgumentException("No session attribute found for key: " + key);
        }

        return value;
    }

    @Override
    public void removeSessionAttribute(String key, HttpSession session) {
        Assert.notNull(key, "Key must not be null");
        Assert.notNull(session, "Session must not be null");

        session.removeAttribute(key);
        if (session.getAttribute(key) != null) {
            throw new IllegalStateException("Failed to remove session attribute for key: " + key);
        }
    }

    @Override
    public void clearSession(HttpSession session) {
        Assert.notNull(session, "Session must not be null");

        session.invalidate();
        if (session.getAttributeNames().hasMoreElements()) {
            throw new IllegalStateException("Failed to clear session attributes");
        }   
    }
}
