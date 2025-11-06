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

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;

/**
 * Utility class for generating JWT secrets.
 * This class provides methods to generate secure Base64 encoded secrets
 * for JWT token signing.
 */
public class JwtSecretGenerator {

    private static final int SECRET_KEY_LENGTH = 32; // 256 bits

    /**
     * Generate a Base64 encoded secret key.
     *
     * @return Base64 encoded secret key
     */
    public static String generateBase64Secret() {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[SECRET_KEY_LENGTH];
        random.nextBytes(keyBytes);
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    /**
     * Generate a hexadecimal encoded secret key.
     *
     * @return Hexadecimal encoded secret key
     */
    public static String generateHexSecret() {
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[SECRET_KEY_LENGTH];
        random.nextBytes(keyBytes);
        
        StringBuilder hexString = new StringBuilder();
        for (byte b : keyBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Main method to generate and print secret keys.
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        String base64Secret = generateBase64Secret();
        String hexSecret = generateHexSecret();
        
        System.out.println("Base64 Secret: " + base64Secret);
        System.out.println("Hex Secret: " + hexSecret);
        
        // Test the secret key with JWT
        testJwtSigning(base64Secret);
    }

    /**
     * Test JWT signing with the generated secret.
     *
     * @param base64Secret the Base64 encoded secret
     */
    private static void testJwtSigning(String base64Secret) {
        try {
            // Decode the secret
            byte[] decodedKey = Base64.getDecoder().decode(base64Secret);
            SecretKey secretKey = Keys.hmacShaKeyFor(decodedKey);
            
            // Create a test JWT
            String jwt = Jwts.builder()
                    .setSubject("testUser")
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
                    .signWith(secretKey)
                    .compact();
            
            System.out.println("Test JWT: " + jwt);
            
            // Parse the JWT
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(jwt);
            
            System.out.println("JWT parsed successfully. Subject: " + claimsJws.getBody().getSubject());
        } catch (Exception e) {
            System.err.println("Error testing JWT signing: " + e.getMessage());
            e.printStackTrace();
        }
    }
}