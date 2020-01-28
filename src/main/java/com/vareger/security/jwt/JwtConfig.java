package com.vareger.security.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class JwtConfig {

    @Value("${vareger.security.pub}")
    private String pubKey;

    @Bean(name = "jwtPublicAlgorithm")
    public Algorithm encryptAlgorithm() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec ks1 = new X509EncodedKeySpec(Base64.getDecoder().decode(pubKey));
        RSAPublicKey pub = (RSAPublicKey) kf.generatePublic(ks1);

        return Algorithm.RSA256(pub, null);
    }

    @Bean("jwtObjectMapper")
    public ObjectMapper initObjectMapper() {
        ObjectMapper mapper = new ObjectMapper();

        return mapper;
    }

}
