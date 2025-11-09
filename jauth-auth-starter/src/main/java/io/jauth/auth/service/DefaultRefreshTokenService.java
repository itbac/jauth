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

package io.jauth.auth.service;

import io.jauth.auth.config.AuthProperties;
import io.jauth.auth.service.AdvancedSignatureGenerator;
import io.jauth.auth.util.SecretResolver;
import io.jauth.core.api.RefreshTokenService;
import io.jauth.core.api.SignatureGenerator;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Default implementation of RefreshTokenService using Redis.
 * This service provides methods for storing, validating, and removing refresh tokens.
 * Refresh tokens are stored in Redis with additional security information.
 */
@Service
public class DefaultRefreshTokenService implements RefreshTokenService {

    private final RedisTemplate<String, String> redisTemplate;
    private final AuthProperties authProperties;
    private final SignatureGenerator signatureGenerator;
    private final SecretResolver secretResolver;

    /**
     * Constructor for DefaultRefreshTokenService.
     *
     * @param redisTemplate the Redis template for string operations
     * @param authProperties the authentication properties
     * @param signatureGenerator the signature generator
     * @param secretResolver the secret resolver
     */
    public DefaultRefreshTokenService(RedisTemplate<String, String> redisTemplate,
                                      AuthProperties authProperties,
                                      SignatureGenerator signatureGenerator,
                                      SecretResolver secretResolver) {
        this.redisTemplate = redisTemplate;
        this.authProperties = authProperties;
        this.signatureGenerator = signatureGenerator;
        this.secretResolver = secretResolver;
    }

    /**
     * Save a refresh token in Redis with additional security information.
     *
     * @param userId the user ID associated with the refresh token
     * @param refreshToken the refresh token to save
     */
    @Override
    public void saveRefreshToken(String userId, String refreshToken) {
        // This method should be called with signature headers extracted from request
        // In the interface we removed the signatureHeaders parameter, but in practice
        // this would be called from methods that have access to the request
        throw new UnsupportedOperationException("Use saveRefreshToken(String, String, HttpServletRequest) instead");
    }

    /**
     * Validate a refresh token and return the associated user ID.
     *
     * @param refreshToken the refresh token to validate
     * @return the user ID if the token is valid, null otherwise
     */
    @Override
    public String validateAndGetUserId(String refreshToken) {
        // This method should be called with signature headers extracted from request
        // In the interface we removed the signatureHeaders parameter, but in practice
        // this would be called from methods that have access to the request
        throw new UnsupportedOperationException("Use validateAndGetUserId(String, HttpServletRequest) instead");
    }

    /**
     * Delete a refresh token from Redis.
     *
     * @param refreshToken the refresh token to delete
     */
    @Override
    public void deleteRefreshToken(String refreshToken) {
        String key = "rt:" + refreshToken;
        redisTemplate.delete(key);
    }
    
    /**
     * Save a refresh token in Redis with additional security information.
     * This method extracts signature headers from the HTTP request.
     *
     * @param userId the user ID associated with the refresh token
     * @param refreshToken the refresh token to save
     * @param request the HTTP request to extract signature headers
     */
    public void saveRefreshToken(String userId, String refreshToken, HttpServletRequest request) {
        Map<String, String> signatureHeaders = extractSignatureHeaders(request);
        String key = "rt:" + refreshToken;
        
        // Create a map to store all the refresh token information
        Map<String, String> tokenInfo = new HashMap<>();
        tokenInfo.put("userId", userId);
        tokenInfo.put("loginTime", signatureHeaders.get("X-login-time"));
        tokenInfo.put("signature", generateSignature(signatureHeaders, request));
        
        // Store the token information in Redis as a hash
        redisTemplate.opsForHash().putAll(key, tokenInfo);
        redisTemplate.expire(key, authProperties.getRefreshToken().getExpiresIn(), TimeUnit.SECONDS);
    }

    /**
     * Validate a refresh token and return the associated user ID.
     * This method extracts signature headers from the HTTP request.
     *
     * @param refreshToken the refresh token to validate
     * @param request the HTTP request to extract signature headers
     * @return the user ID if the token is valid, null otherwise
     */
    public String validateAndGetUserId(String refreshToken, HttpServletRequest request) {
        Map<String, String> signatureHeaders = extractSignatureHeaders(request);
        try {
            String key = "rt:" + refreshToken;
            
            // Check if the token exists
            if (!redisTemplate.hasKey(key)) {
                return null;
            }
            
            // Retrieve token information
            Map<Object, Object> tokenInfo = redisTemplate.opsForHash().entries(key);
            if (tokenInfo.isEmpty()) {
                return null;
            }
            
            String userId = (String) tokenInfo.get("userId");
            String storedLoginTimeStr = (String) tokenInfo.get("loginTime");
            String storedSignature = (String) tokenInfo.get("signature");
            
            if (userId == null || storedLoginTimeStr == null || storedSignature == null) {
                // Invalid token information
                return null;
            }
            
            // Get login time from signature headers
            String loginTimeStr = signatureHeaders.get("X-login-time");
            
            // If login time is provided, validate it
            if (loginTimeStr != null && !loginTimeStr.equals(storedLoginTimeStr)) {
                // Login time doesn't match
                return null;
            }
            
            // Validate the signature
            String currentSignature = generateSignature(signatureHeaders, request);
            if (!storedSignature.equals(currentSignature)) {
                // Signature doesn't match
                return null;
            }
            
            return userId;
        } catch (Exception e) {
            // Any exception means the token is invalid
            return null;
        }
    }

    /**
     * Delete a refresh token from Redis after validating it.
     * This method extracts signature headers from the HTTP request.
     *
     * @param refreshToken the refresh token to delete
     * @param request the HTTP request to extract signature headers for validation
     */
    public void deleteRefreshToken(String refreshToken, HttpServletRequest request) {
        // First validate the refresh token
        String userId = validateAndGetUserId(refreshToken, request);
        if (userId != null) {
            // Token is valid, delete it
            deleteRefreshToken(refreshToken);
        }
    }
    
    /**
     * Generate a signature based on configured headers and HTTP request.
     *
     * @param signatureHeaders the headers used for signature generation
     * @param request the HTTP request used to determine the client and business type
     * @return the generated signature
     */
    private String generateSignature(Map<String, String> signatureHeaders, HttpServletRequest request) {
        if (signatureGenerator instanceof AdvancedSignatureGenerator) {
            return ((AdvancedSignatureGenerator) signatureGenerator).generateSignature(signatureHeaders, request);
        } else {
            // Fallback to global secret if AdvancedSignatureGenerator is not available
            // For this fallback, we need to extract signature headers from the request
            return generateSignature(signatureHeaders);
        }
    }
    
    /**
     * Generate a signature based on configured headers.
     *
     * @param signatureHeaders the headers used for signature generation
     * @return the generated signature
     */
    private String generateSignature(Map<String, String> signatureHeaders) {
        // Use the secret resolver to determine the appropriate secret
        String secret = authProperties.getSecret(); // Fallback to global secret for now
        return signatureGenerator.generateSignature(signatureHeaders);
    }
    
    /**
     * Extract signature headers from the HTTP request.
     *
     * @param request the HTTP request
     * @return a map of signature headers
     */
    private Map<String, String> extractSignatureHeaders(HttpServletRequest request) {
        Map<String, String> signatureHeaders = new HashMap<>();
        
        // Use signatureHeadersForValidation if set, otherwise use signatureHeaders
        List<String> headersToUse = authProperties.getRefreshToken().getSecurity().getSignatureHeadersForValidation();
        if (headersToUse == null || headersToUse.isEmpty()) {
            headersToUse = authProperties.getRefreshToken().getSecurity().getSignatureHeaders();
        }
        
        for (String headerName : headersToUse) {
            String headerValue = request.getHeader(headerName);
            if (headerValue != null) {
                signatureHeaders.put(headerName, headerValue);
            }
        }
        return signatureHeaders;
    }
}