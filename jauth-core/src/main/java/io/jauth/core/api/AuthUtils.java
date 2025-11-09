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

import io.jauth.core.dto.LoginResponse;
import io.jauth.core.dto.RefreshTokenResponse;

/**
 * Authentication utility interface for handling common authentication operations.
 * This interface provides methods for login, refresh token, and logout operations
 * that can be implemented by different modules based on their specific requirements.
 */
public interface AuthUtils {
    
    /**
     * Perform login operation for the given user ID.
     *
     * @param userId the user ID
     * @return the login response containing tokens and related information
     */
    LoginResponse login(String userId);
    
    /**
     * Refresh an access token using a refresh token.
     *
     * @return the refresh token response with result information
     */
    RefreshTokenResponse refreshToken();
    
    /**
     * Logout a user by deleting the refresh token.
     */
    void logout();
}