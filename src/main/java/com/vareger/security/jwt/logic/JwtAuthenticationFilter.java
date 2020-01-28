package com.vareger.security.jwt.logic;

import com.vareger.security.jwt.dto.JwtUserDetails;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private volatile boolean isInit;

    private volatile ClientTokenTool tokenTool;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res,
                                    FilterChain chain) throws IOException,
            ServletException {
        init(req);
        try {
            JwtUserDetails user = tokenTool.getAccessToken(req);

            SecurityContextHolder.getContext()
                                 .setAuthentication(new UsernamePasswordAuthenticationToken(user, "", user
                                         .getAuthorities()));

            chain.doFilter(req, res);
        } catch (Exception e) {
            logger.debug(e.getMessage(), e);
            throw e;
        }
    }

    protected void init(HttpServletRequest request) {
        if (!isInit) {
            ServletContext servletContext = request.getServletContext();
            WebApplicationContext webApplicationContext = WebApplicationContextUtils.getWebApplicationContext(
                    servletContext);
            tokenTool = webApplicationContext.getBean(ClientTokenTool.class);
            isInit = true;
        }
    }


}
