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

package io.jauth.resource;

import io.jauth.core.util.Ed25519KeyGenerator;
import io.jauth.core.util.JwtUtil;
import io.jauth.core.util.UserContext;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;

/**
 * JWT Authentication filter for validating JWT tokens in HTTP requests.
 * This filter intercepts all requests, validates JWT tokens for secured paths,
 * and sets the user context for the request.
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final ResourceSecurityProperties resourceSecurityProperties;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    //公钥验签
    private Map<String, PublicKey> publicKeyMap;

    /**
     * Constructor for JwtAuthenticationFilter.
     *
     * @param resourceSecurityProperties the resource security properties
     */
    public JwtAuthenticationFilter(ResourceSecurityProperties resourceSecurityProperties) {
        this.resourceSecurityProperties = resourceSecurityProperties;
        Map<String, String> publicKeys = resourceSecurityProperties.getPublicKeys();
        if (null != publicKeys && !publicKeys.isEmpty()) {
            publicKeys.forEach((k, v) -> {
                try {
                    PublicKey publicKey = Ed25519KeyGenerator.loadPublicKey(v);
                    publicKeyMap.put(k, publicKey);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
    }

    /**
     * Filter method that processes each request to validate JWT tokens.
     *
     * @param request     the HTTP request
     * @param response    the HTTP response
     * @param filterChain the filter chain
     * @throws ServletException if a servlet error occurs
     * @throws IOException      if an IO error occurs
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        String requestURI = request.getRequestURI();
        
        // Check if the path should be permitted without authentication
        if (isPermitAllPath(requestURI)) {
            filterChain.doFilter(request, response);
            return;
        }
        
        // Check if the path requires authentication
        if (!isSecurePath(requestURI)) {
            filterChain.doFilter(request, response);
            return;
        }
        
        String token = extractToken(request);
        if (token == null) {
            sendUnauthorizedResponse(response, "missing_token", "Missing JWT token");
            return;
        }
        String clientTypeHeaderName = StringUtils.defaultIfBlank(resourceSecurityProperties.getClientTypeHeaderName(), "X-Client-Type");
        String clientType = request.getHeader(clientTypeHeaderName);
        if (clientType == null) {
            sendUnauthorizedResponse(response, "missing_clientType", "Missing X-Client-Type");
            return;
        }
        
        try {
            // Validate token
            Claims claims = JwtUtil.validateToken(publicKeyMap.get(clientType), token, null, null);
            if (claims == null) {
                sendUnauthorizedResponse(response, "invalid_token", "Invalid JWT token");
                return;
            }
            
            // Get user ID from subject
            String userId = claims.getSubject();
            
            // Set user context
            UserContext.setUserId(userId);
            
            // Continue with the filter chain
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            sendUnauthorizedResponse(response, "invalid_token", "Invalid token: " + e.getMessage());
        } finally {
            // Clear user context after request processing
            UserContext.clear();
        }
    }

    /**
     * Extract the JWT token from the Authorization header.
     *
     * @param request the HTTP request
     * @return the JWT token, or null if not found
     */
    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        
        if (header == null || !header.startsWith("Bearer ")) {
            return null;
        }
        
        return header.substring(7);
    }

    /**
     * Check if the request URI matches any permit-all paths.
     *
     * @param requestURI the request URI
     * @return true if the path is permitted without authentication, false otherwise
     */
    private boolean isPermitAllPath(String requestURI) {
        List<String> permitAllPaths = resourceSecurityProperties.getPermitAllPaths();
        if (permitAllPaths != null) {
            for (String pattern : permitAllPaths) {
                if (pathMatcher.match(pattern, requestURI)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Check if the request URI matches any secure paths.
     *
     * @param requestURI the request URI
     * @return true if the path requires authentication, false otherwise
     */
    private boolean isSecurePath(String requestURI) {
        List<String> securePaths = resourceSecurityProperties.getSecurePaths();
        if (securePaths != null) {
            for (String pattern : securePaths) {
                if (pathMatcher.match(pattern, requestURI)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Send an unauthorized response with error details.
     *
     * @param response the HTTP response
     * @param error    the error code
     * @param reason   the error reason
     * @throws IOException if an IO error occurs
     */
    private void sendUnauthorizedResponse(HttpServletResponse response, String error, String reason) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        
        Map<String, String> errorResponse = Map.of(
            "error", error,
            "reason", reason
        );
        
        response.getWriter().write("{\"error\":\"" + error + "\",\"reason\":\"" + reason + "\"}");
    }
}