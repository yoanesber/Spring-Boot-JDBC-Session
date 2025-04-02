package com.yoanesber.form_auth_demo.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.CsrfTokenRequestHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import com.yoanesber.form_auth_demo.handler.CustomLoginFailureHandler;
import com.yoanesber.form_auth_demo.handler.CustomLoginSuccessHandler;
import com.yoanesber.form_auth_demo.handler.CustomLogoutHandler;
import com.yoanesber.form_auth_demo.service.CustomUserDetailsService;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    private final CustomUserDetailsService customUserDetailsService;

    private static final String ROLE_ADMIN = "ADMIN";
    private static final String ROLE_USER = "USER";

    @Value("${error-403-url}")
    private String error403Url;

    @Value("${csrf-repository-name}")
    private String CSRF_REPOSITORY_NAME;

    @Value("#{'${permit-all-request-url}'.split(',')}")
    private String[] permitAllRequestUrl;

    @Value("#{'${permit-admin-request-url}'.split(',')}")
    private String[] permitAdminRequestUrl;

    @Value("#{'${permit-user-request-url}'.split(',')}")
    private String[] permitUserRequestUrl;

    @Value("#{'${csrf-ignored-request-url}'.split(',')}")
    private String[] csrfIgnoredRequestUrl;

    @Value("${login-url}")
    private String loginUrl;

    @Value("${login-success-url}")
    private String loginSuccessUrl;

    @Value("${logout-url}")
    private String logoutUrl;

    @Value("${logout-success-url}")
    private String logoutSuccessUrl;

    @Value("${maximum-session}")
    private int maximumSession;

    @Value("${max-session-prevents-login}")
    private boolean maxSessionPreventsLogin;

    public SecurityConfig(CustomUserDetailsService customUserDetailsService) {
        this.customUserDetailsService = customUserDetailsService;
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(customUserDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
  
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Use HttpSessionCsrfTokenRepository as the default csrf token repository
    // The csrf token is stored in the HttpSession
    @Bean
    public CsrfTokenRepository httpSessionCsrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        
        // Set session attribute name of the csrf token
        repository.setSessionAttributeName(CSRF_REPOSITORY_NAME);

        return repository;
    }

    
    // and CookieCsrfTokenRepository as the alternative csrf token repository
    // The csrf token is stored in a cookie
    @Bean
    public CsrfTokenRepository cookieCsrfTokenRepository() {
        CookieCsrfTokenRepository repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        
        // Set cookie name of the csrf token
        repository.setCookieName(CSRF_REPOSITORY_NAME);
        
        return repository;
    }

    // Use HttpSessionEventPublisher to track session events
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();  // Required for session event tracking
    }

    // Use SessionRegistry to track active sessions
    // This is used to prevent multiple sessions for the same user
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    @Bean
    public AuthenticationSuccessHandler customAuthenticationSuccessHandler(){
        return new CustomLoginSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler customAuthenticationFailureHandler(){
        return new CustomLoginFailureHandler();
    }

    @Bean
    public LogoutSuccessHandler customLogoutSuccessHandler() {
        return new CustomLogoutHandler();
    }

    @Bean
    public CsrfTokenRequestHandler csrfRequestHandler() {
        return new CsrfTokenRequestAttributeHandler()::handle;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(session -> session
                .sessionFixation(sessionFixation -> sessionFixation
                    .migrateSession()) // Migrate session on login to prevent session fixation attacks
                .sessionConcurrency(concurrency -> 
                    concurrency
                        .maximumSessions(maximumSession) // Set maximum sessions per user
                        .maxSessionsPreventsLogin(maxSessionPreventsLogin) // Prevent login if session exists
                        .sessionRegistry(sessionRegistry()) // Enable session tracking
                        .expiredUrl(loginUrl + "?sessionExpired=true") // Redirect to login page if session expired
                )
            )
            .authenticationProvider(authenticationProvider())
            .headers(headers -> headers
                .frameOptions(frame -> frame.deny()) 
                .cacheControl(cache -> cache.disable())
                .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' https://source.unsplash.com; font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com;"))
            )
            .csrf((csrf) -> csrf
                .csrfTokenRepository(httpSessionCsrfTokenRepository())
                .csrfTokenRequestHandler(csrfRequestHandler())
                .ignoringRequestMatchers(csrfIgnoredRequestUrl)
		    )
            .authorizeHttpRequests(auth -> 
                auth.requestMatchers(permitAllRequestUrl).permitAll()
                    .requestMatchers(permitAdminRequestUrl).hasRole(ROLE_ADMIN)
                    .requestMatchers(permitUserRequestUrl).hasRole(ROLE_USER)
                    .anyRequest().authenticated()
            )
            .formLogin(form -> 
                form.loginPage(loginUrl)
                    .defaultSuccessUrl(loginSuccessUrl, true)
                    .successHandler(customAuthenticationSuccessHandler())
                    .failureHandler(customAuthenticationFailureHandler())
                    .permitAll())
            .logout(logout -> 
                logout.logoutUrl(logoutUrl)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
                    .logoutSuccessHandler(customLogoutSuccessHandler())
                    .permitAll())
            .exceptionHandling(exceptionHandling -> 
                exceptionHandling.accessDeniedPage(error403Url));

        return http.build();
    }
}