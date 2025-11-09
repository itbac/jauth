/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.jauth.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Configuration properties for the authentication module.
 * This class holds configuration values for JWT tokens and security settings.
 */
@Component
@ConfigurationProperties(prefix = "jauth")
public class AuthProperties {

    /**
     * Client type specific configurations.
     * This allows different client types (web, app, mini-program) to use different secrets and token strategies.
     */
    private Map<String, ClientTypeConfig> clientType = new HashMap<>();
    
    // Remove the old security field since it's now part of RefreshToken
    
    /**
     * Get client type specific configurations.
     *
     * @return the client type specific configurations map
     */
    public Map<String, ClientTypeConfig> getClientType() {
        return clientType;
    }
    
    /**
     * Set client type specific configurations.
     * This allows different client types (web, app, mini-program) to use different secrets and token strategies.
     *
     * @param clientType the client type specific configurations map to set
     */
    public void setClientType(Map<String, ClientTypeConfig> clientType) {
        this.clientType = clientType;
    }
    
    /**
     * Get the access token configuration.
     *
     * @return the access token configuration
     */
    public AccessToken getAccessToken() {
        // Return the access token configuration from the first client type
        // This is for backward compatibility
        if (clientType != null && !clientType.isEmpty()) {
            ClientTypeConfig firstClientType = clientType.values().iterator().next();
            return firstClientType.getAccessToken();
        }
        // Return a default access token configuration
        return new AccessToken();
    }
    
    /**
     * Get the refresh token configuration.
     *
     * @return the refresh token configuration
     */
    public RefreshToken getRefreshToken() {
        // Return the refresh token configuration from the first client type
        // This is for backward compatibility
        if (clientType != null && !clientType.isEmpty()) {
            ClientTypeConfig firstClientType = clientType.values().iterator().next();
            return firstClientType.getRefreshToken();
        }
        // Return a default refresh token configuration
        return new RefreshToken();
    }
    
    /**
     * Get client secrets map.
     * This is for backward compatibility.
     *
     * @return the client secrets map
     */
    public Map<String, String> getClientSecrets() {
        // Create a map of client secrets from client type configurations
        Map<String, String> clientSecrets = new HashMap<>();
        if (clientType != null) {
            for (Map.Entry<String, ClientTypeConfig> entry : clientType.entrySet()) {
                // We don't have a direct secret in ClientTypeConfig anymore
                // This is just for backward compatibility
                clientSecrets.put(entry.getKey(), "default-secret");
            }
        }
        return clientSecrets;
    }
    
    /**
     * Get business secrets map.
     * This is for backward compatibility.
     *
     * @return the business secrets map
     */
    public Map<String, String> getBusinessSecrets() {
        // Return an empty map for backward compatibility
        return new HashMap<>();
    }
    
    /**
     * Get the global secret.
     * This is for backward compatibility.
     *
     * @return the global secret
     */
    public String getSecret() {
        // Return a default secret for backward compatibility
        return "default-global-secret";
    }



    /**
     * Access token configuration properties.
     */
    public static class AccessToken {
        /**
         * The public key for verifying JWT tokens (Base64 encoded).
         */
        private String publicKey;
        
        /**
         * The private key for signing JWT tokens (Base64 encoded).
         */
        private String privateKey;
        
        /**
         * The signature algorithm for JWT tokens.
         * Supported values: HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, RS256
         * Default is HMAC-SHA256.
         */
        private String algorithm = "HMAC-SHA256";
        
        /**
         * The access token expiration time in seconds.
         */
        private long expiresIn = 3600; // 1 hour
        
        /**
         * Get the public key for verifying JWT tokens.
         *
         * @return the public key (Base64 encoded)
         */
        public String getPublicKey() {
            return publicKey;
        }
        
        /**
         * Set the public key for verifying JWT tokens.
         *
         * @param publicKey the public key to set (Base64 encoded)
         */
        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }
        
        /**
         * Get the private key for signing JWT tokens.
         *
         * @return the private key (Base64 encoded)
         */
        public String getPrivateKey() {
            return privateKey;
        }
        
        /**
         * Set the private key for signing JWT tokens.
         *
         * @param privateKey the private key to set (Base64 encoded)
         */
        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }
        
        /**
         * Get the signature algorithm for JWT tokens.
         *
         * @return the signature algorithm
         */
        public String getAlgorithm() {
            return algorithm;
        }
        
        /**
         * Set the signature algorithm for JWT tokens.
         * Supported values: HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, RS256, RS384, RS512
         *
         * @param algorithm the signature algorithm to set
         */
        public void setAlgorithm(String algorithm) {
            // Validate the algorithm
            if (!"HMAC-SHA256".equals(algorithm) && 
                !"HMAC-SHA384".equals(algorithm) && 
                !"HMAC-SHA512".equals(algorithm) &&
                !"RS256".equals(algorithm) &&
                !"RS384".equals(algorithm) &&
                !"RS512".equals(algorithm)) {
                throw new IllegalArgumentException("Invalid algorithm: " + algorithm + 
                    ". Supported algorithms are: HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, RS256, RS384, RS512");
            }
            this.algorithm = algorithm;
        }
        
        /**
         * Get the access token expiration time in seconds.
         *
         * @return the access token expiration time in seconds
         */
        public long getExpiresIn() {
            return expiresIn;
        }
        
        /**
         * Set the access token expiration time in seconds.
         *
         * @param expiresIn the access token expiration time in seconds
         */
        public void setExpiresIn(long expiresIn) {
            this.expiresIn = expiresIn;
        }
        
        /**
         * Get the secret key.
         * This is for backward compatibility.
         *
         * @return the secret key
         */
        public String getSecret() {
            // Return a default secret for backward compatibility
            return "default-access-token-secret";
        }
    }
    
    /**
     * Refresh token configuration properties.
     */
    public static class RefreshToken {
        /**
         * The refresh token expiration time in seconds.
         */
        private long expiresIn = 86400; // 24 hours
        
        /**
         * Security configuration for refresh tokens.
         */
        private Security security = new Security();
        
        /**
         * Get the refresh token expiration time in seconds.
         *
         * @return the refresh token expiration time in seconds
         */
        public long getExpiresIn() {
            return expiresIn;
        }
        
        /**
         * Set the refresh token expiration time in seconds.
         *
         * @param expiresIn the refresh token expiration time in seconds
         */
        public void setExpiresIn(long expiresIn) {
            this.expiresIn = expiresIn;
        }
        
        /**
         * Get the security configuration for refresh tokens.
         *
         * @return the security configuration
         */
        public Security getSecurity() {
            return security;
        }
        
        /**
         * Set the security configuration for refresh tokens.
         *
         * @param security the security configuration to set
         */
        public void setSecurity(Security security) {
            this.security = security;
        }
    }
    
    /**
     * Security configuration properties.
     */
    public static class Security {
        /**
         * Constants for SameSite cookie attribute values.
         */
        public static final String SAME_SITE_STRICT = "Strict";
        public static final String SAME_SITE_LAX = "Lax";
        public static final String SAME_SITE_NONE = "None";
        
        /**
         * Default hash algorithm for signature generation.
         */
        public static final String DEFAULT_HASH_ALGORITHM = "HMAC-SHA256";
        
        /**
         * The headers to use for generating the signature.
         * If signatureHeadersForValidation is not set, these headers will be used for both
         * signature generation and validation.
         */
        private List<String> signatureHeaders = List.of("User-Agent", "Accept-Language", "X-login-time");
        
        /**
         * The headers to use specifically for signature validation.
         * If not set, signatureHeaders will be used instead.
         * This allows using a subset of headers for validation to reduce computation overhead.
         */
        private List<String> signatureHeadersForValidation;
        
        /**
         * The hash algorithm to use for signature generation.
         * Supported values: MD5, SHA-1, SHA-256, SHA-384, SHA-512, HMAC-SHA256, HMAC-SHA512
         * Default is HMAC-SHA256.
         */
        private String hashAlgorithm = DEFAULT_HASH_ALGORITHM;
        
        /**
         * Cookie configuration.
         * This field is optional and can be null if not configured for certain client types.
         */
        private CookieConfig cookie;

        /**
         * Get the headers to use for generating the signature.
         * If signatureHeadersForValidation is not set, these headers will be used for both
         * signature generation and validation.
         *
         * @return the list of headers
         */
        public List<String> getSignatureHeaders() {
            return signatureHeaders;
        }

        /**
         * Set the headers to use for generating the signature.
         * If signatureHeadersForValidation is not set, these headers will be used for both
         * signature generation and validation.
         *
         * @param signatureHeaders the list of headers to set
         */
        public void setSignatureHeaders(List<String> signatureHeaders) {
            this.signatureHeaders = signatureHeaders;
        }
        
        /**
         * Get the headers to use specifically for signature validation.
         * If not set, signatureHeaders will be used instead.
         * This allows using a subset of headers for validation to reduce computation overhead.
         *
         * @return the list of headers for validation, or null if not set
         */
        public List<String> getSignatureHeadersForValidation() {
            return signatureHeadersForValidation;
        }
        
        /**
         * Set the headers to use specifically for signature validation.
         * If not set, signatureHeaders will be used instead.
         * This allows using a subset of headers for validation to reduce computation overhead.
         *
         * @param signatureHeadersForValidation the list of headers for validation to set
         */
        public void setSignatureHeadersForValidation(List<String> signatureHeadersForValidation) {
            this.signatureHeadersForValidation = signatureHeadersForValidation;
        }
        
        /**
         * Get the hash algorithm to use for signature generation.
         *
         * @return the hash algorithm
         */
        public String getHashAlgorithm() {
            return hashAlgorithm;
        }
        
        /**
         * Set the hash algorithm to use for signature generation.
         * Supported values: MD5, SHA-1, SHA-256, SHA-384, SHA-512, HMAC-SHA256, HMAC-SHA512
         *
         * @param hashAlgorithm the hash algorithm to set
         */
        public void setHashAlgorithm(String hashAlgorithm) {
            // Validate the hash algorithm
            try {
                if (hashAlgorithm.startsWith("HMAC-")) {
                    // For HMAC algorithms, validate the underlying algorithm
                    String underlyingAlgorithm = hashAlgorithm.substring(5); // Remove "HMAC-" prefix
                    Mac.getInstance("Hmac" + underlyingAlgorithm);
                } else {
                    // For standard hash algorithms
                    MessageDigest.getInstance(hashAlgorithm);
                }
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalArgumentException("Unsupported hash algorithm: " + hashAlgorithm);
            }
            this.hashAlgorithm = hashAlgorithm;
        }
        
        /**
         * Get the cookie configuration.
         *
         * @return the cookie configuration, or null if not configured
         */
        public CookieConfig getCookie() {
            return cookie;
        }
        
        /**
         * Set the cookie configuration.
         *
         * @param cookie the cookie configuration to set
         */
        public void setCookie(CookieConfig cookie) {
            this.cookie = cookie;
        }
        
        /**
         * Get the SameSite attribute for cookies.
         * This is for backward compatibility.
         *
         * @return the SameSite attribute value
         */
        public String getCookieSameSite() {
            if (cookie != null) {
                return cookie.getSameSite();
            }
            // Return default value for backward compatibility
            return "Lax";
        }
        
        /**
         * Check if cookies should be secure.
         * This is for backward compatibility.
         *
         * @return true if cookies should be secure, false otherwise
         */
        public boolean isCookieSecure() {
            if (cookie != null) {
                return cookie.isSecure();
            }
            // Return default value for backward compatibility
            return true;
        }
    }
}