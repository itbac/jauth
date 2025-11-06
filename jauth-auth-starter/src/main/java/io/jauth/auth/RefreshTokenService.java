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

package io.jauth.auth;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Refresh token service for managing refresh tokens in Redis.
 * This service provides methods for storing, validating, and removing refresh tokens.
 */
@Service
public class RefreshTokenService {

    private final RedisTemplate<String, String> redisTemplate;
    private final RedisTemplate<String, Long> redisLongTemplate;

    /**
     * Constructor for RefreshTokenService.
     *
     * @param redisTemplate the Redis template for string operations
     * @param redisLongTemplate the Redis template for long operations
     */
    public RefreshTokenService(RedisTemplate<String, String> redisTemplate,
                               RedisTemplate<String, Long> redisLongTemplate) {
        this.redisTemplate = redisTemplate;
        this.redisLongTemplate = redisLongTemplate;
    }

    /**
     * Save a refresh token in Redis.
     *
     * @param userId the user ID associated with the refresh token
     * @param refreshToken the refresh token to save
     * @param loginTime the login time
     */
    public void saveRefreshToken(String userId, String refreshToken, long loginTime) {
        String key = "rt:" + refreshToken;
        redisTemplate.opsForValue().set(key, userId, 24, TimeUnit.HOURS);
        
        // Store login time if provided
        if (loginTime > 0) {
            String loginTimeKey = "rt:login:" + refreshToken;
            redisLongTemplate.opsForValue().set(loginTimeKey, loginTime, 24, TimeUnit.HOURS);
        }
    }

    /**
     * Validate a refresh token and return the associated user ID.
     *
     * @param refreshToken the refresh token to validate
     * @param loginTime the login time to match (can be null)
     * @return the user ID if the token is valid, null otherwise
     */
    public String validateAndGetUserId(String refreshToken, Long loginTime) {
        try {
            String key = "rt:" + refreshToken;
            String userId = redisTemplate.opsForValue().get(key);
            
            if (userId == null) {
                return null;
            }
            
            // If login time is provided, validate it
            if (loginTime != null) {
                String loginTimeKey = "rt:login:" + refreshToken;
                Long storedLoginTime = redisLongTemplate.opsForValue().get(loginTimeKey);
                
                if (storedLoginTime == null || !storedLoginTime.equals(loginTime)) {
                    // Login time doesn't match, invalidate the token
                    deleteRefreshToken(refreshToken);
                    return null;
                }
            }
            
            return userId;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Delete a refresh token from Redis.
     *
     * @param refreshToken the refresh token to delete
     */
    public void deleteRefreshToken(String refreshToken) {
        String key = "rt:" + refreshToken;
        redisTemplate.delete(key);
        
        // Delete associated login time
        String loginTimeKey = "rt:login:" + refreshToken;
        redisTemplate.delete(loginTimeKey);
    }
}