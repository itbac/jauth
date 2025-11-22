package io.jauth.auth.service;

import io.jauth.auth.config.AuthProperties;
import io.jauth.core.api.AccessTokenService;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.util.Map;


@Service
public class DefaultAccessTokenService  implements AccessTokenService {

    private final AuthProperties authProperties;

    private Map<String, PrivateKey> privateKeyMap;

    public DefaultAccessTokenService(AuthProperties authProperties) {
        this.authProperties = authProperties;
    }

    @Override
    public String generateAccessToken(String userId) {
        return "";
    }
}
