package io.jauth.auth.config;

/**
 * Client type specific configuration properties.
 * This class holds configuration values for a specific client type.
 */
public class ClientTypeConfig {
    
    /**
     * Access token configuration for this client type.
     */
    private AuthProperties.AccessToken accessToken = new AuthProperties.AccessToken();
    
    /**
     * Refresh token configuration for this client type.
     */
    private AuthProperties.RefreshToken refreshToken = new AuthProperties.RefreshToken();
    
    /**
     * Get the access token configuration for this client type.
     *
     * @return the access token configuration
     */
    public AuthProperties.AccessToken getAccessToken() {
        return accessToken;
    }
    
    /**
     * Set the access token configuration for this client type.
     *
     * @param accessToken the access token configuration to set
     */
    public void setAccessToken(AuthProperties.AccessToken accessToken) {
        this.accessToken = accessToken;
    }
    
    /**
     * Get the refresh token configuration for this client type.
     *
     * @return the refresh token configuration
     */
    public AuthProperties.RefreshToken getRefreshToken() {
        return refreshToken;
    }
    
    /**
     * Set the refresh token configuration for this client type.
     *
     * @param refreshToken the refresh token configuration to set
     */
    public void setRefreshToken(AuthProperties.RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
    }
}