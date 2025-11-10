package io.jauth.core.api;


public interface AccessTokenService {

    /**
     * Generate an access token for the given user ID.
     *
     * @param userId the user ID to include in the token
     * @return the generated access token
     */
    String generateAccessToken(String userId);
}
