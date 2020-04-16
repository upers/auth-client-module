package com.github.uper.security.jwt.logic;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.uper.security.jwt.dto.JwtRefreshUserDetails;
import com.github.uper.security.jwt.dto.JwtUserDetails;
import com.github.uper.security.jwt.dto.TokenDto;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

@Component
public class TokenTool extends ClientTokenTool {

    private static final Logger log = LogManager.getLogger(TokenTool.class);

    private final String refreshTokenPrefix;

    private final Long accessTokenExpirationTime;

    private final Long refreshTokenExpirationTime;

    private final String authCodeParamName;

    private final Algorithm algorithm;

    public TokenTool(
            @Value("${security.access.token.prefix}") String accessTokenPrefix,
            @Value("${security.refresh.token.prefix}") String refreshTokenPrefix,
            @Value("${security.access.token.expiration}") Long accessTokenExpirationTime,
            @Value("${security.refresh.token.expiration}") Long refreshTokenExpirationTime,
            IdGovUaProperty idGovUaProperty,
            @Qualifier("jwtPrivateAlgorithm") Algorithm algorithm,
            @Qualifier("jwtObjectMapper") ObjectMapper mapper) {
        super(accessTokenPrefix, algorithm, mapper);
        this.algorithm = algorithm;
        this.refreshTokenPrefix = refreshTokenPrefix;
        this.accessTokenExpirationTime = accessTokenExpirationTime;
        this.refreshTokenExpirationTime = refreshTokenExpirationTime;
        this.authCodeParamName = idGovUaProperty.getLoginCodeParamName();
    }

    public String createAccessToken(JwtUserDetails jwtUserDetails) throws JsonProcessingException {
        String accessTokenPayload = mapper.writeValueAsString(jwtUserDetails);
        return accessTokenPrefix + JWT.create().withSubject(accessTokenPayload)
                                      .withExpiresAt(new Date(System.currentTimeMillis() + accessTokenExpirationTime))
                                      .sign(algorithm);
    }

    public String createAccessToken(User user, String userType) throws JsonProcessingException {
        var jwtUserDetails = new JwtUserDetails(user);
        jwtUserDetails.setUserType(userType);

        return createAccessToken(jwtUserDetails);
    }

    public String createRefreshToken(User user, String userType) throws JsonProcessingException {
        var jwtRefreshUserDetails = new JwtRefreshUserDetails(user);
        jwtRefreshUserDetails.setUserType(userType);

        return createRefreshToken(jwtRefreshUserDetails);
    }

    public String createRefreshToken(JwtRefreshUserDetails jwtRefreshUserDetails) throws JsonProcessingException {
        String refreshTokenPayload = mapper.writeValueAsString(jwtRefreshUserDetails);

        return refreshTokenPrefix + JWT.create().withSubject(refreshTokenPayload)
                                       .withExpiresAt(new Date(System.currentTimeMillis() + refreshTokenExpirationTime))
                                       .sign(algorithm);
    }


    /**
     * Map refresh token from request header "Authorization".
     *
     * @param request {@link HttpServletRequest}
     * @return {@link JwtRefreshUserDetails}
     */
    public JwtRefreshUserDetails getRefreshToken(HttpServletRequest request) {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (token == null)
            throw new BadCredentialsException("Token not found");
        if (!token.startsWith(refreshTokenPrefix))
            throw new BadCredentialsException("Token prefix is not correct");

        // parse the token.
        String payload = jwtVerifier
                .verify(token.replace(refreshTokenPrefix, "")).getSubject();

        try {
            return mapper.readValue(payload, JwtRefreshUserDetails.class);
        } catch (IOException e) {
            log.error(e.getMessage());
        }

        return null;
    }

    /**
     * Retrieve authentication code from  {@link HttpServletRequest} parameter.
     * If doesn't find parameter throw {@link BadCredentialsException}
     * @param request {@link HttpServletRequest}
     * @return auth code
     */
    public String getAuthCode(HttpServletRequest request) {
        String code = request.getParameter(authCodeParamName);
        if (code == null)
            throw new BadCredentialsException("Code not found");

        return code;
    }
    /**
     * Send token to client by using {@link HttpServletResponse#getOutputStream()}. </br>
     * Token object is: {@link TokenDto}
     *
     * @throws IOException
     */
    public void sendTokensToUser(HttpServletResponse res, String accessToken, String refreshToken) throws IOException {
        res.addHeader(HttpHeaders.AUTHORIZATION, accessToken);
        res.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_UTF8_VALUE);
        res.setStatus(HttpStatus.OK.value());
        mapper.writeValue(res.getOutputStream(), new TokenDto(accessToken, refreshToken));
    }

}
