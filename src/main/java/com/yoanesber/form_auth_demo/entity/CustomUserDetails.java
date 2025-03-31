package com.yoanesber.form_auth_demo.entity;

import java.time.Instant;
import java.util.Collection;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class CustomUserDetails implements UserDetails {
    private User user;

    public CustomUserDetails(User user) {
        this.user = user;
    }

    public static CustomUserDetails build(User user) {
        return new CustomUserDetails(user);
    }

    public Long getId() {
        return this.user.getId();
    }
    
    @Override
    public String getUsername() {
        return this.user.getUserName();
    }

    @Override
    public String getPassword() {
        return this.user.getPassword();
    }

    public String getEmail() {
        return this.user.getEmail();
    }

    public String getFirstName() {
        return this.user.getFirstName();
    }

    public String getLastName() {
        return this.user.getLastName();
    }

    @Override
    public boolean isEnabled() {
        return this.user.isEnabled();
    }

    @Override
    public boolean isAccountNonExpired() {
        return this.user.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.user.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.user.isCredentialsNonExpired();
    }

    public Instant getLastLogin() {
        return this.user.getLastLogin();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.user.getUserRoles().stream().map(userRole -> new SimpleGrantedAuthority(userRole.getRole().getName()))
            .collect(Collectors.toList());
    }

    @Override
    public String toString() {
        return "CustomUserDetails {" +
                "user=" + user +
                ", username='" + getUsername() + '\'' +
                ", password='" + getPassword() + '\'' +
                ", email='" + getEmail() + '\'' +
                ", firstName='" + getFirstName() + '\'' +
                ", lastName='" + getLastName() + '\'' +
                ", lastLogin=" + getLastLogin() +
                '}';
    }
}
