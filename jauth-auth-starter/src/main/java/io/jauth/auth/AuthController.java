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

import io.jauth.core.TokenGenerator;
import io.jauth.core.UserServiceAdapter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

    private final UserServiceAdapter userServiceAdapter;
    private final TokenGenerator tokenGenerator;
    private final RefreshTokenService refreshTokenService;

    /**
     * Constructor for AuthController.
     *
     * @param userServiceAdapter  the user service adapter for validating credentials
     * @param tokenGenerator      the token generator for creating JWT tokens
     * @param refreshTokenService the refresh token service for handling token refresh
     */
    public AuthController(UserServiceAdapter userServiceAdapter, TokenGenerator tokenGenerator,
                          RefreshTokenService refreshTokenService) {
        this.userServiceAdapter = userServiceAdapter;
        this.tokenGenerator = tokenGenerator;
        this.refreshTokenService = refreshTokenService;
    }

    /**
     * Authenticate a user and generate access and refresh tokens.
     *
     * @param request the login request containing username and password
     * @param response the HTTP response for setting cookies
     * @return a response entity with the generated tokens or an error message
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletResponse response) {
        try {
            // Authenticate user
            if (!userServiceAdapter.authenticate(request.getUsername(), request.getPassword())) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_credentials");
                errorResponse.put("error_description", "Invalid username or password");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }

            // Get user ID
            String userId = userServiceAdapter.getUserIdByUsername(request.getUsername());
            if (userId == null) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "user_not_found");
                errorResponse.put("error_description", "User not found");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }

            // Generate tokens
            long expireMillis = 3600000; // 1 hour
            String accessToken = tokenGenerator.generateAccessToken(userId, expireMillis);
            String refreshToken = tokenGenerator.generateRefreshToken();
            long loginTime = System.currentTimeMillis();

            // Store refresh token
            refreshTokenService.saveRefreshToken(userId, refreshToken, loginTime);

            // Set refresh token cookie
            Cookie refreshTokenCookie = new Cookie("refresh_token", refreshToken);
            refreshTokenCookie.setHttpOnly(true);
            refreshTokenCookie.setSecure(true);
            refreshTokenCookie.setPath("/");
            refreshTokenCookie.setMaxAge(86400); // 24 hours
            // Note: setSameSite is not available in all Servlet API versions
            // We'll handle SameSite through other means if needed
            response.addCookie(refreshTokenCookie);

            // Create response
            Map<String, Object> tokenResponse = new HashMap<>();
            tokenResponse.put("access_token", accessToken);
            tokenResponse.put("expires_in", expireMillis / 1000);

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
     * @param response the HTTP response for setting cookies
     * @param httpRequest the HTTP request for reading cookies
     * @return a response entity with the new tokens or an error message
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody(required = false) RefreshRequest request,
                                          HttpServletResponse response,
                                          HttpServletRequest httpRequest) {
        try {
            String refreshToken = null;
            Long loginTime = null;

            // Check if refresh token is provided in request body (for mobile apps)
            if (request != null && request.getRefreshToken() != null) {
                refreshToken = request.getRefreshToken();
                if (request.getLoginTime() != null) {
                    loginTime = request.getLoginTime();
                }
            } else {
                // Check if refresh token is provided in cookies (for web)
                Cookie[] cookies = httpRequest.getCookies();
                if (cookies != null) {
                    for (Cookie cookie : cookies) {
                        if ("refresh_token".equals(cookie.getName())) {
                            refreshToken = cookie.getValue();
                            break;
                        }
                    }
                }
            }

            if (refreshToken == null) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "missing_refresh_token");
                errorResponse.put("error_description", "Refresh token is required");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // Validate refresh token
            String userId = refreshTokenService.validateAndGetUserId(refreshToken, loginTime);
            if (userId == null) {
                Map<String, String> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_refresh_token");
                errorResponse.put("error_description", "Invalid or expired refresh token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }

            // Generate new tokens
            long expireMillis = 3600000; // 1 hour
            String newAccessToken = tokenGenerator.generateAccessToken(userId, expireMillis);
            String newRefreshToken = tokenGenerator.generateRefreshToken();
            long newLoginTime = System.currentTimeMillis();

            // Delete old refresh token and save new one
            refreshTokenService.deleteRefreshToken(refreshToken);
            refreshTokenService.saveRefreshToken(userId, newRefreshToken, newLoginTime);

            // Create response
            Map<String, Object> tokenResponse = new HashMap<>();
            tokenResponse.put("access_token", newAccessToken);
            tokenResponse.put("expires_in", expireMillis / 1000);

            // If request came from web (cookie), set new cookie
            if (request == null || request.getRefreshToken() == null) {
                Cookie refreshTokenCookie = new Cookie("refresh_token", newRefreshToken);
                refreshTokenCookie.setHttpOnly(true);
                refreshTokenCookie.setSecure(true);
                refreshTokenCookie.setPath("/");
                refreshTokenCookie.setMaxAge(86400); // 24 hours
                // Note: setSameSite is not available in all Servlet API versions
                response.addCookie(refreshTokenCookie);
            } else {
                // If request came from app (body), return new refresh token and login time
                tokenResponse.put("refresh_token", newRefreshToken);
                tokenResponse.put("login_time", newLoginTime);
            }

            return ResponseEntity.ok(tokenResponse);
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
     * @param request the HTTP request for reading cookies
     * @param response the HTTP response for clearing cookies
     * @return a response entity with a success message or an error message
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            // Get refresh token from cookies
            String refreshToken = null;
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("refresh_token".equals(cookie.getName())) {
                        refreshToken = cookie.getValue();
                        break;
                    }
                }
            }

            if (refreshToken != null) {
                // Delete refresh token
                refreshTokenService.deleteRefreshToken(refreshToken);

                // Clear refresh token cookie
                Cookie refreshTokenCookie = new Cookie("refresh_token", "");
                refreshTokenCookie.setHttpOnly(true);
                refreshTokenCookie.setSecure(true);
                refreshTokenCookie.setPath("/");
                refreshTokenCookie.setMaxAge(0); // Expire immediately
                // Note: setSameSite is not available in all Servlet API versions
                response.addCookie(refreshTokenCookie);
            }

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