package io.jauth.auth;

import io.jauth.auth.util.RsaKeyPairGenerator;
import io.jauth.core.util.JwtUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.*;

class RsaKeyPairGeneratorTest {

    @Test
    void testRsaKeyPairGeneration() {
        // Generate RSA key pair
        RsaKeyPairGenerator.RsaKeyPair keyPair = RsaKeyPairGenerator.generateRsaKeyPair();
        
        String publicKey = keyPair.getPublicKey();
        String privateKey = keyPair.getPrivateKey();
        
        // Verify keys are not null or empty
        assertNotNull(publicKey, "Public key should not be null");
        assertNotNull(privateKey, "Private key should not be null");
        assertFalse(publicKey.isEmpty(), "Public key should not be empty");
        assertFalse(privateKey.isEmpty(), "Private key should not be empty");
        
        // Verify keys are valid Base64 encoded strings
        assertDoesNotThrow(() -> Base64.getDecoder().decode(publicKey), "Public key should be valid Base64");
        assertDoesNotThrow(() -> Base64.getDecoder().decode(privateKey), "Private key should be valid Base64");
        
        System.out.println("Generated Public Key: " + publicKey);
        System.out.println("Generated Private Key: " + privateKey);
    }
    
    @Test
    void testJwtSigningWithGeneratedRsaKeys() {
        // Generate RSA key pair
        RsaKeyPairGenerator.RsaKeyPair keyPair = RsaKeyPairGenerator.generateRsaKeyPair();
        
        String publicKey = keyPair.getPublicKey();
        String privateKey = keyPair.getPrivateKey();
        
        // Create JwtUtil with generated RSA keys
        JwtUtil jwtUtil = JwtUtil.withKeys("RS256", publicKey, privateKey);
        
        // Generate a token
        String userId = "test-user-123";
        long expireMillis = 3600000; // 1 hour
        String token = jwtUtil.generateAccessToken(userId, expireMillis);
        
        // Verify token is not null or empty
        assertNotNull(token, "JWT token should not be null");
        assertFalse(token.isEmpty(), "JWT token should not be empty");
        
        // Validate the token
        String extractedUserId = jwtUtil.getUserIdFromToken(token);
        assertEquals(userId, extractedUserId, "Extracted user ID should match original");
        
        // Verify token is not expired
        assertFalse(jwtUtil.isTokenExpired(token), "Token should not be expired");
        
        System.out.println("Generated JWT Token: " + token);
        System.out.println("Extracted User ID: " + extractedUserId);
    }
    
    @Test
    void testMultipleRsaKeySizes() {
        // Test with different RSA key sizes by modifying the generator
        // For now, we'll just verify that the default 2048-bit keys work correctly
        
        // Generate multiple RSA key pairs
        for (int i = 0; i < 3; i++) {
            RsaKeyPairGenerator.RsaKeyPair keyPair = RsaKeyPairGenerator.generateRsaKeyPair();
            
            String publicKey = keyPair.getPublicKey();
            String privateKey = keyPair.getPrivateKey();
            
            // Verify keys are not null or empty
            assertNotNull(publicKey, "Public key should not be null");
            assertNotNull(privateKey, "Private key should not be null");
            assertFalse(publicKey.isEmpty(), "Public key should not be empty");
            assertFalse(privateKey.isEmpty(), "Private key should not be empty");
            
            // Create JwtUtil with generated RSA keys
            JwtUtil jwtUtil = JwtUtil.withKeys("RS256", publicKey, privateKey);
            
            // Generate and validate a token
            String userId = "test-user-" + i;
            String token = jwtUtil.generateAccessToken(userId, 3600000);
            
            assertNotNull(token, "JWT token should not be null");
            assertEquals(userId, jwtUtil.getUserIdFromToken(token), "Extracted user ID should match original");
        }
    }
}