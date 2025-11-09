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
import io.jauth.core.api.TokenGenerator;
import io.jauth.core.util.JwtUtil;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * JWT implementation of TokenGenerator.
 * This service generates access and refresh tokens using JWT and UUID respectively.
 */
@Service
public class DefaultTokenGenerator implements TokenGenerator {

    private final JwtUtil jwtUtil;
    private final AuthProperties authProperties;

    /**
     * Constructor for DefaultTokenGenerator.
     *
     * @param jwtUtil the JWT utility for token operations
     * @param authProperties the authentication properties
     */
    public DefaultTokenGenerator(JwtUtil jwtUtil, AuthProperties authProperties) {
        this.jwtUtil = jwtUtil;
        this.authProperties = authProperties;
    }

    /**
     * Generate an access token for the given user ID.
     *
     * @param userId the user ID to include in the token
     * @return the generated access token
     */
    @Override
    public String generateAccessToken(String userId) {
        long expireMillis = authProperties.getAccessToken().getExpiresIn() * 1000;
        return jwtUtil.generateAccessToken(userId, expireMillis);
    }

    /**
     * Generate a refresh token.
     *
     * @return the generated refresh token
     */
    @Override
    public String generateRefreshToken() {
        return UUID.randomUUID().toString();
    }
}