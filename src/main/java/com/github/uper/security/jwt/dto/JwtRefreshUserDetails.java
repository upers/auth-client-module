package com.github.uper.security.jwt.dto;

import org.springframework.security.core.userdetails.User;

import java.util.UUID;

public class JwtRefreshUserDetails extends JwtUserDetails {

    private String refreshTokenSalt;

    public JwtRefreshUserDetails() {
    }

    public JwtRefreshUserDetails(User user) {
        super(user);
        this.refreshTokenSalt = UUID.randomUUID().toString();
    }

    public String getRefreshTokenSalt() {
        return refreshTokenSalt;
    }

    public void setRefreshTokenSalt(String refreshTokenSalt) {
        this.refreshTokenSalt = refreshTokenSalt;
    }

    @Override
    public String toString() {
        return "JWTRefreshUserDetails[" +
                "salt='" + refreshTokenSalt + '\'' + super.toString() +
                ']';
    }
}
