package com.github.uper.security.jwt.logic;

public class IdGovUaProperty {
    private String loginUrl;
    private String loginCodeParamName;

    public String getLoginUrl() {
        return loginUrl;
    }

    public void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    public String getLoginCodeParamName() {
        return loginCodeParamName;
    }

    public void setLoginCodeParamName(String loginCodeParamName) {
        this.loginCodeParamName = loginCodeParamName;
    }
}
