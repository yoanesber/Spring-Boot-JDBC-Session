package com.yoanesber.form_auth_demo.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;

@Configuration
@EnableJdbcHttpSession
public class JdbcSessionConfig {
    /*
     * This class is used to configure JDBC session management in Spring Boot.
     * It enables the use of JDBC for session management, allowing sessions to be stored in a database.
     * This is useful for distributed applications where session data needs to be shared across multiple instances.
     
     * Note: Make sure to have the necessary dependencies for JDBC session management in your project.
     * For example, you may need to include the spring-session-jdbc dependency in your Maven or Gradle configuration.
     * 
     * You can also customize the session management settings by providing additional configuration options
     * such as session timeout, session table name, etc.
     */
}