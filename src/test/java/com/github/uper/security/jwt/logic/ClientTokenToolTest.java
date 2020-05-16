package com.github.uper.security.jwt.logic;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.uper.security.jwt.dto.JwtGrantedAuthority;
import com.github.uper.security.jwt.dto.JwtUserDetails;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

public class ClientTokenToolTest {

    private static final String accessTokenPrefix = "Bearer ";

    private static final String refreshTokenPrefix = "Refresh ";

    private static final long accessTokenExpirationTime = 111115000l;

    private static final long refreshTokenExpirationTime = 10000l;

    private ClientTokenTool clientTokenTool;

    private TokenTool tokenTool;

    private Algorithm algorithm;

    private Algorithm publicAlgorithm;

    @Before
    public void before() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        String prKey = FileUtils.readFileFromClassPath("pk.key");
        String pubKey = FileUtils.readFileFromClassPath("pub.key");
        algorithm = encryptAlgorithm(prKey, pubKey);
        publicAlgorithm = publicEncryptAlgorithm(pubKey);

        var idGovUaProperty = new IdGovUaProperty();
        idGovUaProperty.setLoginUrl("/gov-ua/login");
        idGovUaProperty.setLoginCodeParamName("code");

        clientTokenTool = new ClientTokenTool(accessTokenPrefix, publicAlgorithm, new ObjectMapper());
        tokenTool = new TokenTool(accessTokenPrefix,
                refreshTokenPrefix,
                accessTokenExpirationTime,
                refreshTokenExpirationTime,
                idGovUaProperty,
                algorithm,
                new ObjectMapper());
    }


    @Test
    public void validToken() throws JsonProcessingException {
        User admin = buildUser("admin", "read", "write");
        String accessToken = tokenTool.createAccessToken(admin);

        HttpServletRequest accessRequest = Mockito.mock(HttpServletRequest.class);
        when(accessRequest.getHeader(HttpHeaders.AUTHORIZATION))
                .thenReturn(accessTokenPrefix + accessToken);

        JwtUserDetails jwtUserDetails = clientTokenTool.getAccessToken(accessRequest);
        String userName = jwtUserDetails.getEmail();
        Set<String> authorities = jwtUserDetails.getAuthorities()
                                                .stream()
                                                .map(JwtGrantedAuthority::getAuthority)
                                                .collect(Collectors.toSet());

        assertEquals( "admin", userName, "Username is not correct");
        assertTrue(authorities.contains("read"), "Token does not contain 'read' authority");
        assertTrue(authorities.contains("write"), "Token does not contain 'write' authority");
        assertEquals(2, authorities.size(), "Authorities is not correct");
    }

    @Test(expected = BadCredentialsException.class)
    public void nonAuthHeader() throws JsonProcessingException {
        HttpServletRequest accessRequest = Mockito.mock(HttpServletRequest.class);
        when(accessRequest.getHeader(HttpHeaders.AUTHORIZATION))
                .thenReturn(null);

        clientTokenTool.getAccessToken(accessRequest);
    }

    @Test(expected = TokenExpiredException.class)
    public void expiredToken() throws JsonProcessingException {
        var idGovUaProperty = new IdGovUaProperty();
        idGovUaProperty.setLoginUrl("/gov-ua/login");
        idGovUaProperty.setLoginCodeParamName("code");

        TokenTool tokenTool = new TokenTool(accessTokenPrefix,
                refreshTokenPrefix,
                1l,
                refreshTokenExpirationTime,
                idGovUaProperty,
                algorithm,
                new ObjectMapper());

        User admin = buildUser("admin", "read", "write");
        String accessToken = tokenTool.createAccessToken(admin);

        HttpServletRequest accessRequest = Mockito.mock(HttpServletRequest.class);
        when(accessRequest.getHeader(HttpHeaders.AUTHORIZATION))
                .thenReturn(accessTokenPrefix + accessToken);

        sleep(1000);
        clientTokenTool.getAccessToken(accessRequest);
    }

    @Test(expected = SignatureVerificationException.class)
    public void wrongPubKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        User admin = buildUser("admin", "read", "write");
        String accessToken = tokenTool.createAccessToken(admin);

        HttpServletRequest accessRequest = Mockito.mock(HttpServletRequest.class);
        when(accessRequest.getHeader(HttpHeaders.AUTHORIZATION))
                .thenReturn(accessTokenPrefix + accessToken);

        String prKey = FileUtils.readFileFromClassPath("pk.key");
        String pubKey = FileUtils.readFileFromClassPath("wrong-pub.key");
        Algorithm wrongPubAlgorithm = encryptAlgorithm(prKey, pubKey);
        clientTokenTool = new ClientTokenTool(accessTokenPrefix, wrongPubAlgorithm, new ObjectMapper());

        clientTokenTool.getAccessToken(accessRequest);
    }

    private User buildUser(String username, String... authorities) {
        return new User(
                username,
                "123",
                AuthorityUtils.createAuthorityList(authorities)
        );
    }

    private Algorithm encryptAlgorithm(String pk, String pub) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(java.util.Base64.getDecoder().decode(pk));
        RSAPrivateKey prK = (RSAPrivateKey) kf.generatePrivate(ks);
        X509EncodedKeySpec ks1 = new X509EncodedKeySpec(Base64.getDecoder().decode(pub));
        RSAPublicKey pubK = (RSAPublicKey) kf.generatePublic(ks1);

        return Algorithm.RSA256(pubK, prK);
    }


    private Algorithm publicEncryptAlgorithm(String pubKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec ks1 = new X509EncodedKeySpec(Base64.getDecoder().decode(pubKey));
        RSAPublicKey pub = (RSAPublicKey) kf.generatePublic(ks1);

        return Algorithm.RSA256(pub, null);
    }


    private void sleep(int ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }
}
