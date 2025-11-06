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
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for JwtSecretGenerator.
 */
class JwtSecretGeneratorTest {

    /**
     * Test that generated Base64 secret has correct length.
     */
    @Test
    void testGenerateBase64Secret() {
        String secret = JwtSecretGenerator.generateBase64Secret();
        assertNotNull(secret);
        assertFalse(secret.isEmpty());
        
        // Decode and check length (should be 32 bytes = 256 bits)
        byte[] decoded = Base64.getDecoder().decode(secret);
        assertEquals(32, decoded.length);
    }

    /**
     * Test that generated hex secret has correct length.
     */
    @Test
    void testGenerateHexSecret() {
        String secret = JwtSecretGenerator.generateHexSecret();
        assertNotNull(secret);
        assertFalse(secret.isEmpty());
        
        // Check length (should be 64 characters for 32 bytes in hex)
        assertEquals(64, secret.length());
    }

    /**
     * Test that the generated secret can be used to sign and parse a JWT.
     */
    @Test
    void testJwtSigningWithGeneratedSecret() {
        String base64Secret = JwtSecretGenerator.generateBase64Secret();
        
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
        
        assertNotNull(jwt);
        assertFalse(jwt.isEmpty());
        
        // Parse the JWT
        Jws<Claims> claimsJws = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(jwt);
        
        assertEquals("testUser", claimsJws.getBody().getSubject());
    }
}