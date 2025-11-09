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

package io.jauth.demo.auth.controller;

import io.jauth.core.api.AuthUtils;
import io.jauth.core.api.RefreshTokenService;
import io.jauth.core.api.TokenGenerator;
import io.jauth.demo.auth.api.UserService;
import io.jauth.core.dto.LoginResponse;
import io.jauth.core.dto.RefreshTokenResponse;
import io.jauth.core.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Authentication controller for handling login, refresh and logout requests.
 * This controller provides REST endpoints for user authentication and token management.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserService userService;
    @Autowired
    private TokenGenerator tokenGenerator;
    @Autowired
    private RefreshTokenService refreshTokenService;
    @Autowired
    private JwtUtil jwtUtil;
    @Autowired
    private AuthUtils authUtils;

    /**
     * Default constructor for AuthController.
     */
    public AuthController() {
        // Default constructor for Spring autowiring
    }

    /**
     * Authenticate a user and generate access and refresh tokens.
     *
     * @param request the login request containing username and password
     * @return a response entity with the generated tokens or an error message
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            // Authenticate user
            String userId = userService.authenticate(request.getUsername(), request.getPassword());
            if (null == userId) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_credentials");
                errorResponse.put("error_description", "Invalid username or password");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }
            // Use AuthUtils to perform login (this will generate tokens and save refresh token in Redis)
            // Cookie setting is now handled internally by AuthUtils
            LoginResponse loginResponse = authUtils.login(userId);

            // Create response for mobile clients
            Map<String, Object> tokenResponse = new HashMap<>();
            tokenResponse.put("access_token", loginResponse.getAccessToken());
            tokenResponse.put("expires_in", loginResponse.getAccessTokenExpiresIn());
            tokenResponse.put("refresh_token", loginResponse.getRefreshToken());
            tokenResponse.put("login_time", loginResponse.getLoginTime());

            return ResponseEntity.ok(tokenResponse);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "authentication_failed");
            errorResponse.put("error_description", "Authentication failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Refresh an access token using a refresh token.
     *
     * @param request the refresh request containing the refresh token
     * @return a response entity with the new tokens or an error message
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody(required = false) RefreshRequest request) {
        try {
            // Use AuthUtils to refresh token
            // Token extraction and cookie setting are now handled internally by AuthUtils
            // For web clients, it reads refresh token from cookies
            // For mobile clients, it reads refresh token from headers (X-refresh-Token)
            // Login time is read from header X-login-time for both web and mobile clients
            RefreshTokenResponse refreshTokenResponse = authUtils.refreshToken();
            
            // Handle the response based on the result
            if (refreshTokenResponse.isSuccess()) {
                // Success case
                // Create response
                Map<String, Object> tokenResponse = new HashMap<>();
                tokenResponse.put("access_token", refreshTokenResponse.getAccessToken());
                tokenResponse.put("expires_in", refreshTokenResponse.getAccessTokenExpiresIn());
                tokenResponse.put("refresh_token", refreshTokenResponse.getRefreshToken());
                tokenResponse.put("login_time", refreshTokenResponse.getLoginTime());

                return ResponseEntity.ok(tokenResponse);
            } else {
                // Error cases
                switch (refreshTokenResponse.getResult()) {
                    case RefreshTokenResponse.RESULT_INVALID_TOKEN:
                        Map<String, String> invalidTokenResponse = new HashMap<>();
                        invalidTokenResponse.put("error", "invalid_refresh_token");
                        invalidTokenResponse.put("error_description", "Invalid or expired refresh token");
                        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(invalidTokenResponse);
                    case RefreshTokenResponse.RESULT_MISSING_TOKEN:
                        Map<String, String> missingTokenResponse = new HashMap<>();
                        missingTokenResponse.put("error", "missing_refresh_token");
                        missingTokenResponse.put("error_description", "Refresh token is required");
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(missingTokenResponse);
                    case RefreshTokenResponse.RESULT_INTERNAL_ERROR:
                    default:
                        Map<String, String> internalErrorResponse = new HashMap<>();
                        internalErrorResponse.put("error", "internal_error");
                        internalErrorResponse.put("error_description", "An internal error occurred");
                        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(internalErrorResponse);
                }
            }
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "token_refresh_failed");
            errorResponse.put("error_description", "Token refresh failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Logout a user by deleting the refresh token.
     *
     * @return a response entity with a success message or an error message
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        try {
            // Use AuthUtils to logout (token extraction and cookie clearing are handled internally by AuthUtils)
            authUtils.logout();

            Map<String, String> successResponse = new HashMap<>();
            successResponse.put("message", "Successfully logged out");
            return ResponseEntity.ok(successResponse);
        } catch (Exception e) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "logout_failed");
            errorResponse.put("error_description", "Logout failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Login request DTO.
     */
    public static class LoginRequest {
        private String username;
        private String password;

        /**
         * Get the username.
         *
         * @return the username
         */
        public String getUsername() {
            return username;
        }

        /**
         * Set the username.
         *
         * @param username the username to set
         */
        public void setUsername(String username) {
            this.username = username;
        }

        /**
         * Get the password.
         *
         * @return the password
         */
        public String getPassword() {
            return password;
        }

        /**
         * Set the password.
         *
         * @param password the password to set
         */
        public void setPassword(String password) {
            this.password = password;
        }
    }

    /**
     * Refresh request DTO.
     */
    public static class RefreshRequest {
        private String refreshToken;
        private Long loginTime;

        /**
         * Get the refresh token.
         *
         * @return the refresh token
         */
        public String getRefreshToken() {
            return refreshToken;
        }

        /**
         * Set the refresh token.
         *
         * @param refreshToken the refresh token to set
         */
        public void setRefreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
        }

        /**
         * Get the login time.
         *
         * @return the login time
         */
        public Long getLoginTime() {
            return loginTime;
        }

        /**
         * Set the login time.
         *
         * @param loginTime the login time to set
         */
        public void setLoginTime(Long loginTime) {
            this.loginTime = loginTime;
        }
    }
}