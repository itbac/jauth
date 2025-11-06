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

package io.jauth.demo.auth.service;

import io.jauth.core.TokenGenerator;
import org.springframework.stereotype.Service;

/**
 * Demo implementation of TokenGenerator.
 * This service generates access and refresh tokens for authenticated users.
 */
@Service
public class DemoTokenGenerator implements TokenGenerator {
    
    /**
     * Generate an access token for the given user ID.
     *
     * @param userId the user ID to include in the token
     * @param expireMillis the expiration time in milliseconds
     * @return the generated access token
     */
    @Override
    public String generateAccessToken(String userId, long expireMillis) {
        // In a real implementation, you would use JwtUtil to generate the token
        // For this demo, we'll return a placeholder
        return "access-token-for-" + userId;
    }
    
    /**
     * Generate a refresh token.
     *
     * @return the generated refresh token
     */
    @Override
    public String generateRefreshToken() {
        // In a real implementation, you would generate a proper refresh token
        // For this demo, we'll return a placeholder
        return "refresh-token";
    }
}