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

import io.jauth.core.util.JwtUtil;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for JwtUtil class.
 */
public class JwtUtilTest {

    @Test
    public void testConstructorWithValid32CharSecret() {
        // Given
        String validSecret = "a".repeat(32); // 32 characters

        // When/Then
        JwtUtil jwtUtil = JwtUtil.withSecret(validSecret);
        assertNotNull(jwtUtil);
    }
    
    @Test
    public void testConstructorWithValid64CharSecret() {
        // Given
        String validSecret = "a".repeat(64); // 64 characters

        // When/Then
        JwtUtil jwtUtil = JwtUtil.withSecret(validSecret);
        assertNotNull(jwtUtil);
    }
    
    @Test
    public void testConstructorWithValid128CharSecret() {
        // Given
        String validSecret = "a".repeat(128); // 128 characters

        // When/Then
        JwtUtil jwtUtil = JwtUtil.withSecret(validSecret);
        assertNotNull(jwtUtil);
    }

    @Test
    public void testConstructorWithNullSecret() {
        // Given
        String nullSecret = null;

        // When/Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class, 
            () -> JwtUtil.withSecret(nullSecret)
        );
        
        // The actual error message is "Secret cannot be null for HMAC algorithms"
        assertEquals("Secret cannot be null for HMAC algorithms", exception.getMessage());
    }

    @Test
    public void testConstructorWithInvalidLengthSecret() {
        // Given
        String shortSecret = "ShortSecret"; // 11 characters

        // When/Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class, 
            () -> JwtUtil.withSecret(shortSecret)
        );
        
        assertTrue(exception.getMessage().contains("Secret must be"));
    }
    
    @Test
    public void testConstructorWith33CharSecret() {
        // Given
        String secret33 = "a".repeat(33); // 33 characters

        // When/Then
        // 33 characters should be valid, so no exception should be thrown
        JwtUtil jwtUtil = JwtUtil.withSecret(secret33);
        assertNotNull(jwtUtil);
    }
    
    @Test
    public void testConstructorWith100CharSecret() {
        // Given
        String secret100 = "a".repeat(100); // 100 characters

        // When/Then
        // 100 characters should be valid, so no exception should be thrown
        JwtUtil jwtUtil = JwtUtil.withSecret(secret100);
        assertNotNull(jwtUtil);
    }
    
    @Test
    public void testConstructorWith500CharSecret() {
        // Given
        String secret500 = "a".repeat(500); // 500 characters

        // When/Then
        // 500 characters should be valid, so no exception should be thrown
        JwtUtil jwtUtil = JwtUtil.withSecret(secret500);
        assertNotNull(jwtUtil);
    }
}