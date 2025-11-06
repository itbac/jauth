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

package io.jauth.core;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import io.jsonwebtoken.security.WeakKeyException;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * JWT Utility class for handling JWT token creation and validation.
 * This class provides methods to generate, validate and parse JWT tokens.
 * 
 * <p>Security considerations for secret keys:
 * <ul>
 *   <li>Allowed lengths: 32, 64, or 128 characters</li>
 *   <li>Key must contain sufficient entropy (randomness) for security</li>
 * </ul>
 * </p>
 */
public class JwtUtil {

    private final SecretKey secretKey;
    private static final int[] ALLOWED_SECRET_LENGTHS = {32, 64, 128};

    /**
     * Constructor for JwtUtil.
     *
     * @param secret the secret key for signing JWT tokens. Must be exactly 32, 64, or 128 characters long.
     * @throws IllegalArgumentException if the secret is null or not exactly 32, 64, or 128 characters long
     */
    public JwtUtil(String secret) {
        // Check for null first
        if (secret == null) {
            throw new IllegalArgumentException("Secret key cannot be null");
        }
        
        // Check if the length is one of the allowed lengths
        boolean isValidLength = false;
        for (int allowedLength : ALLOWED_SECRET_LENGTHS) {
            if (secret.length() == allowedLength) {
                isValidLength = true;
                break;
            }
        }
        
        if (!isValidLength) {
            StringBuilder allowedLengthsStr = new StringBuilder();
            for (int i = 0; i < ALLOWED_SECRET_LENGTHS.length; i++) {
                if (i > 0) {
                    allowedLengthsStr.append(", ");
                }
                allowedLengthsStr.append(ALLOWED_SECRET_LENGTHS[i]);
            }
            
            throw new IllegalArgumentException(
                "Secret key must be exactly " + allowedLengthsStr.toString() + " characters long. " +
                "Provided secret length: " + secret.length() + " characters.");
        }
        
        // Try to create the secret key
        try {
            this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        } catch (WeakKeyException e) {
            throw new IllegalArgumentException(
                "Secret key is too weak. " + e.getMessage(), e);
        }
    }

    /**
     * Generate a JWT access token for the given user ID.
     *
     * @param userId the user ID to include in the token
     * @param expireMillis the expiration time in milliseconds
     * @return the generated JWT token
     */
    public String generateAccessToken(String userId, long expireMillis) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expireMillis);

        return Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(secretKey)
                .compact();
    }

    /**
     * Parse a JWT access token and return its claims.
     *
     * @param token the JWT token to parse
     * @return the claims contained in the token
     * @throws JwtException if the token is invalid
     */
    public Claims parseAccessToken(String token) throws JwtException {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            return claimsJws.getBody();
        } catch (SignatureException ex) {
            throw new JwtException("Invalid JWT signature");
        } catch (MalformedJwtException ex) {
            throw new JwtException("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            throw new JwtException("Expired JWT token");
        } catch (UnsupportedJwtException ex) {
            throw new JwtException("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            throw new JwtException("JWT claims string is empty");
        }
    }

    /**
     * Validate a JWT access token.
     *
     * @param token the JWT token to validate
     * @return true if the token is valid, false otherwise
     */
    public boolean validateAccessToken(String token) {
        try {
            parseAccessToken(token);
            return true;
        } catch (JwtException ex) {
            return false;
        }
    }
}