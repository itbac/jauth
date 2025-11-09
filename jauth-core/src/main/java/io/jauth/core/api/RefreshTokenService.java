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

package io.jauth.core.api;

/**
 * Service interface for managing refresh tokens.
 * This interface provides methods for saving, validating, and deleting refresh tokens.
 */
public interface RefreshTokenService {
    
    /**
     * Save a refresh token with user ID.
     *
     * @param userId the user ID
     * @param refreshToken the refresh token
     */
    void saveRefreshToken(String userId, String refreshToken);
    
    /**
     * Validate a refresh token and get the user ID.
     *
     * @param refreshToken the refresh token
     * @return the user ID if valid, null otherwise
     */
    String validateAndGetUserId(String refreshToken);
    
    /**
     * Delete a refresh token.
     *
     * @param refreshToken the refresh token to delete
     */
    void deleteRefreshToken(String refreshToken);
}