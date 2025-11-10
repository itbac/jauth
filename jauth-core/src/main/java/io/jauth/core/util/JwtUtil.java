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

package io.jauth.core.util;

import io.jsonwebtoken.*;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

/**
 * Utility class for JWT operations.
 * This class provides methods for generating and validating JWT tokens.
 */
public class JwtUtil {


    /**
     * Generate an access token for the given user ID.
     *
     * @param userId       the user ID to include in the token
     * @param expireMillis the expiration time in milliseconds
     * @return the generated access token
     */
    public static String generateAccessToken(PrivateKey privateKey, String userId, long expireMillis, String issuer, String audience) {
        if (privateKey == null) {
            throw new IllegalStateException("Private key is required");
        }
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expireMillis);

        JwtBuilder builder = Jwts.builder()
                .subject(userId) // 载荷：用户ID（非敏感）
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(privateKey, Jwts.SIG.EdDSA);// 最新版正确用法：Jwts.SIG.Ed25519
        //发布者
        if (null != issuer && !issuer.isEmpty()) {
            builder.issuer(issuer);
        }
        //观众
        if (null != audience && !audience.isEmpty()) {
            builder.setAudience(audience);
        }
        return builder.compact();
    }

    /**
     * Validate a token and get the claims.
     *
     * @param token the token to validate
     * @return the claims if valid, null otherwise
     */
    public static Claims validateToken(PublicKey publicKey, String token, String issuer, String audience) {
        if (publicKey == null) {
            throw new IllegalStateException("Public key is required for asymmetric algorithms");
        }
        try {
            JwtParserBuilder jwtParserBuilder = Jwts.parser()
                    .verifyWith(publicKey);
            //发布者
            if (null != issuer && !issuer.isEmpty()) {
                jwtParserBuilder.requireIssuer(issuer);
            }
            //观众
            if (null != audience && !audience.isEmpty()) {
                jwtParserBuilder.requireAudience(audience);
            }
            Jws<Claims> claimsJws = jwtParserBuilder.build().parseSignedClaims(token);
            JwsHeader header = claimsJws.getHeader();
            if (!header.getOrDefault("alg", "").equals("EdDSA")) {
                return null;
            }
            Claims payload = claimsJws.getPayload();
            return payload;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Get user ID from a token.
     *
     * @param token the token
     * @return the user ID if valid, null otherwise
     */
    public static String getUserIdFromToken(PublicKey publicKey, String token) {
        Claims claims = validateToken(publicKey, token, null, null);
        return claims != null ? claims.getSubject() : null;
    }

    /**
     * Check if a token is expired.
     *
     * @param token the token
     * @return true if expired, false otherwise
     */
    public static boolean isTokenExpired(PublicKey publicKey, String token) {
        Claims claims = validateToken(publicKey, token, null, null);
        return claims == null || claims.getExpiration().before(new Date());
    }
}