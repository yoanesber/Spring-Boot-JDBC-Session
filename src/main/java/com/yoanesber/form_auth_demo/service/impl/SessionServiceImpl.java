package com.yoanesber.form_auth_demo.service.impl;

import jakarta.servlet.http.HttpSession;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.time.format.DateTimeFormatter;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

import com.yoanesber.form_auth_demo.entity.CustomUserDetails;
import com.yoanesber.form_auth_demo.service.SessionService;

@Service
public class SessionServiceImpl implements SessionService {

    private final JdbcTemplate jdbcTemplate;

    private final SessionRegistry sessionRegistry;

    private static DateTimeFormatter FORMATTER;

    private static final String timezone = "Asia/Jakarta"; // Set your timezone here

    private static final String datetimePattern = "yyyy-MM-dd HH:mm:ss";

    public SessionServiceImpl(JdbcTemplate jdbcTemplate, 
        SessionRegistry sessionRegistry) {
        this.jdbcTemplate = jdbcTemplate;
        this.sessionRegistry = sessionRegistry;

        FORMATTER = DateTimeFormatter.ofPattern(datetimePattern)
            .withZone(timezone != null ? ZoneId.of(timezone) : ZoneId.systemDefault());
    }
    
    @Override
    public List<Map<String, Object>> getAllActiveSessions() {
        // Get all active principals from the session registry
        List<Map<String, Object>> sessions = this.getSessions();
        if (sessions == null || sessions.isEmpty()) {
            return List.of(); // Return an empty list if no sessions found
        }

        // Create a list to hold session information
        List<Map<String, Object>> sessionInfoMap = new ArrayList<>();

        // Iterate through each session and extract relevant information
        for (Map<String, Object> session : sessions) {
            // Create a map to store session information
            Map<String, Object> sessionInfo = new HashMap<>();
            sessionInfo.put("username", session.get("principal_name").toString());
            sessionInfo.put("sessionId", session.get("session_id").toString());

            sessionInfo.put("creationTime", FORMATTER
                .format(Instant.ofEpochMilli((long) session.get("creation_time"))));

            sessionInfo.put("lastAccessTime", FORMATTER
                .format(Instant.ofEpochMilli((long) session.get("last_access_time"))));

            sessionInfo.put("expiryTime", FORMATTER
                .format(Instant.ofEpochMilli((long) session.get("expiry_time"))));

            // Get the session attributes
            sessionInfo.put("ipAddress", this.getSessionAttribute("ipAddress", session.get("session_id").toString()));
            sessionInfo.put("userRole", this.getSessionAttribute("userRole", session.get("session_id").toString()));

            sessionInfo.put("lastLogin", FORMATTER
                .format((Instant) this.getSessionAttribute("lastLogin", 
                    session.get("session_id").toString())));

            // Add the session info to the map
            sessionInfoMap.add(sessionInfo);
        }
        
        return sessionInfoMap;
    }

    @Override
    public void setSessionAttribute(String attributeName, Object value, HttpSession session) {
        Assert.notNull(attributeName, "Attribute name must not be null");
        Assert.notNull(value, "Value must not be null");
        Assert.notNull(session, "Session must not be null");

        session.setAttribute(attributeName, value);
    }

    @Override
    public List<Map<String, Object>> getSessions() {
        String sql = """
            SELECT * FROM SPRING_SESSION
            WHERE PRINCIPAL_NAME IS NOT NULL""";

        List<Map<String, Object>> sessions = jdbcTemplate.queryForList(sql);
        if (sessions == null || sessions.isEmpty()) {
            return List.of(); // Return an empty list if no sessions found
        }

        return sessions;
    }

    @Override
    public Map<String, Object> getSession(String sessionId) {
        Assert.notNull(sessionId, "Session ID must not be null");

        String sql = "SELECT * FROM SPRING_SESSION WHERE SESSION_ID = ?";
        Map<String, Object> session = jdbcTemplate.queryForMap(sql, sessionId);
        if (session == null || session.isEmpty()) {
            return new HashMap<>(); // Return an empty map if no session found
        }

        return session;
    }

    @Override
    public Object getSessionAttribute(String attributeName, HttpSession session) {
        Assert.notNull(attributeName, "Attribute name must not be null");
        Assert.notNull(session, "Session must not be null");

        return session.getAttribute(attributeName);
    }

    @Override
    public Object getSessionAttribute(String attributeName, String sessionId) {
        Assert.notNull(attributeName, "Attribute name must not be null");
        Assert.notNull(sessionId, "Session ID must not be null");

        String sql = """
            SELECT SA.ATTRIBUTE_BYTES 
            FROM SPRING_SESSION S 
            LEFT JOIN SPRING_SESSION_ATTRIBUTES SA 
            ON S.PRIMARY_ID = SA.SESSION_PRIMARY_ID 
            WHERE S.SESSION_ID = ? 
                AND SA.ATTRIBUTE_NAME = ?""";
    
        try {
            byte[] bytes = jdbcTemplate.queryForObject(sql, byte[].class, sessionId, attributeName);
            if (bytes != null) {
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
                return ois.readObject();
            }
        } catch (Exception e) {
            return null; // Return null if the attribute is not found or an error occurs
        }
        return null;
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
    public void invalidateOldSessions(String username, String sessionId) {
        Assert.notNull(username, "Username must not be null");
        Assert.notNull(sessionId, "Session ID must not be null");
        
        List<Object> principals = sessionRegistry.getAllPrincipals();
        for (Object principal : principals) {
            if (principal instanceof CustomUserDetails) {
                CustomUserDetails userDetails = (CustomUserDetails) principal;
                if (userDetails.getUsername().equals(username)) {
                    List<SessionInformation> sessions = sessionRegistry.getAllSessions(principal, false);
                    
                    // Invalidate old sessions of the user except the current session
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
    public void removeSessionAttribute(String attributeName, HttpSession session) {
        Assert.notNull(attributeName, "Attribute name must not be null");
        Assert.notNull(session, "Session must not be null");

        session.removeAttribute(attributeName);
        if (session.getAttribute(attributeName) != null) {
            throw new IllegalStateException("Failed to remove session attribute: " + attributeName);
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
