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
import io.jauth.auth.util.RequestContextUtil;
import io.jauth.core.api.AccessTokenService;
import io.jauth.core.api.AuthUtils;
import io.jauth.core.api.RefreshTokenService;
import io.jauth.core.dto.LoginResponse;
import io.jauth.core.dto.RefreshTokenResponse;
import io.netty.util.internal.StringUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.codec.binary.StringUtils;

/**
 * Web-based implementation of AuthUtils for JAuth.
 * This class provides helper methods for authentication and token management in web environments.
 */
public class DefaultAuthUtils implements AuthUtils {
    
    private final AuthProperties authProperties;
    private final AccessTokenService accessTokenService;
    private final RefreshTokenService refreshTokenService;

    public DefaultAuthUtils(AuthProperties authProperties, AccessTokenService accessTokenService, RefreshTokenService refreshTokenService) {
        this.authProperties = authProperties;
        this.accessTokenService = accessTokenService;
        this.refreshTokenService = refreshTokenService;
    }

    /**
     * Check if the current request is from a web client (browser).
     * This is determined by checking if the request contains a specific header
     * or by checking the User-Agent header for browser-specific identifiers.
     *
     * @return true if the request is from a web client, false otherwise
     */
    private boolean isWebRequest() {
        HttpServletRequest request = RequestContextUtil.getCurrentRequest();
        if (request == null) {
            return false;
        }
        // Alternatively, check the User-Agent header for browser-specific identifiers
        String userAgent = request.getHeader("User-Agent");
        if (null != userAgent && !userAgent.isEmpty()) {
            // Common browser identifiers
            String[] browsers = {"Mozilla", "Chrome", "Safari", "Firefox", "Edge", "Opera", "MSIE"};
            for (String browser : browsers) {
                if (userAgent.contains(browser)) {
                    return true;
                }
            }
        }
        // Check if the request contains a specific header that indicates a web client
        // This could be a custom header that web clients send
        String webClientHeader = request.getHeader("X-Web-Client");
        if (StringUtils.equals("true", webClientHeader)) {
            return true;
        }
        
        // By default, assume it's not a web request
        return false;
    }
    
    /**
     * Perform login operation for the given user ID.
     *
     * @param userId the user ID
     * @return the login response containing tokens and related information
     */
    @Override
    public LoginResponse login(String userId) {
        if (StringUtil.isNullOrEmpty(userId)) {
            throw new IllegalArgumentException("Parameter error: userId");
        }
        // Get current request
        HttpServletRequest request = RequestContextUtil.getCurrentRequest();
        
        // Generate tokens with default expiration time
        String accessToken = null;
        try {
            accessToken = accessTokenService.generateAccessToken(userId);
        } catch (Exception e) {
            throw new IllegalArgumentException("error: generateAccessToken");
        }
        String refreshToken = refreshTokenService.generateRefreshToken();
        long loginTime = System.currentTimeMillis();
        
        // Save refresh token in Redis
        // We need to cast to DefaultRefreshTokenService to use the HttpServletRequest method
        if (refreshTokenService instanceof DefaultRefreshTokenService) {
            ((DefaultRefreshTokenService) refreshTokenService).saveRefreshToken(userId, refreshToken, request);
        } else {
            // Fallback to the interface method - now we need to handle this differently
            throw new UnsupportedOperationException("RefreshTokenService implementation must support HttpServletRequest-based methods");
        }
        
        // Set refresh token cookie for web clients
        if (isWebRequest()) {
            setRefreshTokenCookie(refreshToken);
        }
        
        // Create and return login response
        return new LoginResponse(
            accessToken,
            refreshToken,
            loginTime,
            (int) authProperties.getAccessToken().getExpiresIn() // Access token expiration time in seconds
        );
    }
    
    /**
     * Refresh an access token using a refresh token.
     * This method automatically extracts the refresh token and login time from the request.
     * For web clients, it reads from cookies.
     * For mobile clients, it reads from headers.
     *
     * @return the refresh token response with result information
     */
    @Override
    public RefreshTokenResponse refreshToken() {
        HttpServletRequest request = RequestContextUtil.getCurrentRequest();
        if (request == null) {
            return new RefreshTokenResponse(RefreshTokenResponse.RESULT_INTERNAL_ERROR);
        }
        
        // Extract refresh token from request
        String refreshToken = null;
        
        // For web clients, read from cookies
        if (isWebRequest()) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("refresh_token".equals(cookie.getName())) {
                        refreshToken = cookie.getValue();
                        break;
                    }
                }
            }
        } else {
            // For mobile clients, read from headers
            refreshToken = request.getHeader("X-refresh-Token");
        }
        
        // If we don't have a refresh token, return missing token error
        if (refreshToken == null) {
            return new RefreshTokenResponse(RefreshTokenResponse.RESULT_MISSING_TOKEN);
        }
        
        // Extract login time from header for both web and mobile clients
        Long loginTime = null;
        String loginTimeStr = request.getHeader("X-login-time");
        if (loginTimeStr != null) {
            try {
                loginTime = Long.parseLong(loginTimeStr);
            } catch (NumberFormatException e) {
                // Ignore invalid login time
            }
        }
        
        try {
            // Validate refresh token with signature
            String userId;
            if (refreshTokenService instanceof DefaultRefreshTokenService) {
                userId = ((DefaultRefreshTokenService) refreshTokenService).validateAndGetUserId(refreshToken, request);
            } else {
                // Fallback to the interface method - now we need to handle this differently
                throw new UnsupportedOperationException("RefreshTokenService implementation must support HttpServletRequest-based methods");
            }
            
            if (userId == null) {
                // Determine the specific error reason
                // Note: In a more sophisticated implementation, RefreshTokenService could return
                // more detailed error information
                return new RefreshTokenResponse(RefreshTokenResponse.RESULT_INVALID_TOKEN);
            }
            
            // Generate new tokens
            String accessToken = accessTokenService.generateAccessToken(userId);
            String newRefreshToken = refreshTokenService.generateRefreshToken();
            long newLoginTime = System.currentTimeMillis();
            
            // Delete old refresh token and save new one with signature in Redis
            // We don't need to validate again since we already did it above
            refreshTokenService.deleteRefreshToken(refreshToken);
            
            // Save new refresh token
            if (refreshTokenService instanceof DefaultRefreshTokenService) {
                ((DefaultRefreshTokenService) refreshTokenService).saveRefreshToken(userId, newRefreshToken, request);
            } else {
                // Fallback to the interface method - now we need to handle this differently
                throw new UnsupportedOperationException("RefreshTokenService implementation must support HttpServletRequest-based methods");
            }
            
            // Set refresh token cookie for web clients
            if (isWebRequest()) {
                setRefreshTokenCookie(newRefreshToken);
            }
            
            // Create and return refresh token response
            return new RefreshTokenResponse(
                accessToken,
                newRefreshToken,
                newLoginTime,
                (int) authProperties.getAccessToken().getExpiresIn() // Access token expiration time in seconds
            );
        } catch (Exception e) {
            return new RefreshTokenResponse(RefreshTokenResponse.RESULT_INTERNAL_ERROR);
        }
    }
    
    /**
     * Logout a user by deleting the refresh token and clearing the cookie.
     * This method automatically extracts the refresh token from the request.
     * For web clients, it reads from cookies.
     * For mobile clients, it reads from headers.
     */
    @Override
    public void logout() {
        HttpServletRequest request = RequestContextUtil.getCurrentRequest();
        if (request == null) {
            return;
        }
        
        String refreshToken = null;
        
        // For web clients, read from cookies
        if (isWebRequest()) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("refresh_token".equals(cookie.getName())) {
                        refreshToken = cookie.getValue();
                        break;
                    }
                }
            }
        } else {
            // For mobile clients, read from headers
            refreshToken = request.getHeader("X-refresh-Token");
        }
        
        // Validate and delete refresh token from Redis if it exists and is valid
        if (refreshToken != null) {
            // First validate the refresh token
            String userId;
            if (refreshTokenService instanceof DefaultRefreshTokenService) {
                userId = ((DefaultRefreshTokenService) refreshTokenService).validateAndGetUserId(refreshToken, request);
            } else {
                // Fallback to the interface method - now we need to handle this differently
                throw new UnsupportedOperationException("RefreshTokenService implementation must support HttpServletRequest-based methods");
            }
            
            // If the token is valid, delete it
            if (userId != null) {
                refreshTokenService.deleteRefreshToken(refreshToken);
            }
        }
        
        // Clear refresh token cookie if it's a web request
        if (isWebRequest()) {
            HttpServletResponse response = RequestContextUtil.getCurrentResponse();
            if (response != null) {
                // Use header-based approach to clear cookie with SameSite attribute
                String sameSite = authProperties.getRefreshToken().getSecurity().getCookieSameSite();
                
                // Build the cookie header for clearing
                StringBuilder cookieHeader = new StringBuilder();
                cookieHeader.append("refresh_token=");
                cookieHeader.append("; Path=/");
                cookieHeader.append("; HttpOnly");
                
                // Add Secure flag if configured
                if (authProperties.getRefreshToken().getSecurity().isCookieSecure()) {
                    cookieHeader.append("; Secure");
                }
                
                // Add SameSite attribute
                cookieHeader.append("; SameSite=").append(sameSite);
                
                // Add Max-Age=0 to expire the cookie
                cookieHeader.append("; Max-Age=0");
                
                response.addHeader("Set-Cookie", cookieHeader.toString());
            }
        }
    }
    
    /**
     * Set a refresh token cookie in the HTTP response.
     * This method should only be called for web clients.
     *
     * @param refreshToken the refresh token to set in the cookie
     */
    private void setRefreshTokenCookie(String refreshToken) {
        HttpServletResponse response = RequestContextUtil.getCurrentResponse();
        if (response != null) {
            // Use header-based approach to set cookie with SameSite attribute
            // This is needed because Cookie.setSameSite() is not available in all Servlet API versions
            String sameSite = authProperties.getRefreshToken().getSecurity().getCookieSameSite();
            
            // Build the cookie header
            StringBuilder cookieHeader = new StringBuilder();
            cookieHeader.append("refresh_token=").append(refreshToken);
            cookieHeader.append("; Path=/");
            cookieHeader.append("; HttpOnly");
            
            // Add Secure flag if configured
            if (authProperties.getRefreshToken().getSecurity().isCookieSecure()) {
                cookieHeader.append("; Secure");
            }
            
            // Add SameSite attribute
            cookieHeader.append("; SameSite=").append(sameSite);
            
            // Add Max-Age
            cookieHeader.append("; Max-Age=").append(authProperties.getRefreshToken().getExpiresIn());
            
            response.addHeader("Set-Cookie", cookieHeader.toString());
        }
    }
}