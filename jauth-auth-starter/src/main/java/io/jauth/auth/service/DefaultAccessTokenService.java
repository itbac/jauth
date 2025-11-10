package io.jauth.auth.service;

import io.jauth.core.api.AccessTokenService;
import org.springframework.stereotype.Service;


@Service
public class DefaultAccessTokenService  implements AccessTokenService {
    @Override
    public String generateAccessToken(String userId) {
        return "";
    }
}
