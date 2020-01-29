package com.github.uper.security.jwt.dto;

import org.springframework.security.core.userdetails.User;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class JwtUserDetails {

    private String username;

    private Set<JwtGrantedAuthority> authorities;

    private boolean accountNonExpired;

    private boolean accountNonLocked;

    private boolean credentialsNonExpired;

    private boolean enabled;

    private String salt;

    public JwtUserDetails() {
    }

    public JwtUserDetails(User user) {
        this.username = user.getUsername();
        this.accountNonExpired = user.isAccountNonExpired();
        this.accountNonLocked = user.isAccountNonLocked();
        this.credentialsNonExpired = user.isCredentialsNonExpired();
        this.enabled = user.isEnabled();
        this.authorities = user.getAuthorities().stream().map(grand -> new JwtGrantedAuthority(grand.getAuthority()))
                .collect(Collectors.toSet());
        this.salt = UUID.randomUUID().toString();
    }

    @Override
    public String toString() {
        return "JWTUserDetails [username=" + username + ", authorities=" + authorities + ", accountNonExpired="
                + accountNonExpired + ", accountNonLocked=" + accountNonLocked + ", credentialsNonExpired="
                + credentialsNonExpired + ", enabled=" + enabled + "]";
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Set<JwtGrantedAuthority> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(Set<JwtGrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    public void setAccountNonExpired(boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
    }

    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }

    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    public void setCredentialsNonExpired(boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }
}
