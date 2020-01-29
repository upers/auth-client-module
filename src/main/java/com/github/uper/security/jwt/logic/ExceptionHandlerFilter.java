package com.github.uper.security.jwt.logic;

import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.uper.security.jwt.dto.SecurityErrorDto;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ExceptionHandlerFilter extends OncePerRequestFilter {

    private final ObjectMapper objectMapper;

    public ExceptionHandlerFilter() {
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws IOException {
        try {
            filterChain.doFilter(request, response);
        } catch (TokenExpiredException | UsernameNotFoundException | BadCredentialsException | SignatureVerificationException e) {
            sendResponse(request, response, HttpStatus.UNAUTHORIZED, e.getMessage());
        } catch (Exception e) {
            sendResponse(request, response, HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
        }
    }

    protected void sendResponse(HttpServletRequest request, HttpServletResponse response, HttpStatus httpStatus, String exMsg)
            throws IOException {
        SecurityErrorDto errorMsgDto = new SecurityErrorDto(httpStatus, exMsg, request.getRequestURI());
        String msg = objectMapper.writeValueAsString(errorMsgDto);
        response.setStatus(httpStatus.value());
        response.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        response.getWriter().write(msg);
        response.flushBuffer();
    }

}
