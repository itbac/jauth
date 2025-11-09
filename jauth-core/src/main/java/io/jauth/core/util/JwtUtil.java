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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

/**
 * Utility class for JWT operations.
 * This class provides methods for generating and validating JWT tokens.
 */
public class JwtUtil {
    
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final SecretKey secretKey;
    private final SignatureAlgorithm algorithm;
    
    /**
     * Private constructor to handle all cases.
     *
     * @param algorithm the signature algorithm
     * @param secret the secret for HMAC algorithms
     * @param publicKey the public key for asymmetric algorithms
     * @param privateKey the private key for asymmetric algorithms
     */
    private JwtUtil(SignatureAlgorithm algorithm, String secret, String publicKey, String privateKey) {
        this.algorithm = algorithm;
        
        if (isHmacAlgorithm(algorithm)) {
            // Initialize HMAC key
            if (secret == null) {
                throw new IllegalArgumentException("Secret cannot be null for HMAC algorithms");
            }
            
            // Check secret length - must be at least 32 characters
            if (secret.length() < 32) {
                throw new IllegalArgumentException("Secret must be at least 32 characters long");
            }
            
            this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            this.privateKey = null;
            this.publicKey = null;
        } else if (isEcdsaAlgorithm(algorithm)) {
            // Initialize ECDSA keys
            try {
                if (privateKey != null) {
                    byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("EC");
                    this.privateKey = keyFactory.generatePrivate(keySpec);
                } else {
                    this.privateKey = null;
                }
                
                if (publicKey != null) {
                    byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("EC");
                    this.publicKey = keyFactory.generatePublic(keySpec);
                } else {
                    this.publicKey = null;
                }
                
                this.secretKey = null;
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid ECDSA keys: " + e.getMessage(), e);
            }
        } else {
            // Initialize RSA or RSASSA-PSS keys
            try {
                if (privateKey != null) {
                    byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    this.privateKey = keyFactory.generatePrivate(keySpec);
                } else {
                    this.privateKey = null;
                }
                
                if (publicKey != null) {
                    byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    this.publicKey = keyFactory.generatePublic(keySpec);
                } else {
                    this.publicKey = null;
                }
                
                this.secretKey = null;
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid RSA keys: " + e.getMessage(), e);
            }
        }
    }
    
    /**
     * Factory method for JwtUtil with default HMAC algorithm (HS256) and secret key.
     *
     * @param secret the secret key for HMAC algorithms
     * @return JwtUtil instance
     * @throws IllegalArgumentException if the secret is invalid
     */
    public static JwtUtil withSecret(String secret) {
        return withSecret("HS256", secret);
    }
    
    /**
     * Factory method for JwtUtil with HMAC algorithm and secret key.
     *
     * @param algorithm the signature algorithm to use (HS256, HS384, HS512)
     * @param secret the secret key for HMAC algorithms
     * @return JwtUtil instance
     * @throws IllegalArgumentException if the secret is invalid
     */
    public static JwtUtil withSecret(String algorithm, String secret) {
        SignatureAlgorithm alg = parseAlgorithm(algorithm);
        
        // Ensure it's an HMAC algorithm
        if (!isHmacAlgorithm(alg)) {
            throw new IllegalArgumentException("This factory method only supports HMAC algorithms: HS256, HS384, HS512");
        }
        
        return new JwtUtil(alg, secret, null, null);
    }
    
    /**
     * Factory method for JwtUtil with default ECDSA algorithm (ES256) and public key only.
     *
     * @param publicKey the public key for token validation (Base64 encoded)
     * @return JwtUtil instance
     * @throws IllegalArgumentException if the key is invalid
     */
    public static JwtUtil withPublicKey(String publicKey) {
        return withPublicKey("ES256", publicKey);
    }
    
    /**
     * Factory method for JwtUtil with asymmetric algorithm and public key only.
     *
     * @param algorithm the signature algorithm to use (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512)
     * @param publicKey the public key for token validation (Base64 encoded)
     * @return JwtUtil instance
     * @throws IllegalArgumentException if the key is invalid
     */
    public static JwtUtil withPublicKey(String algorithm, String publicKey) {
        SignatureAlgorithm alg = parseAlgorithm(algorithm);
        
        // Ensure it's not an HMAC algorithm
        if (isHmacAlgorithm(alg)) {
            throw new IllegalArgumentException("Use withSecret() factory method for HMAC algorithms");
        }
        
        return new JwtUtil(alg, null, publicKey, null);
    }
    
    /**
     * Factory method for JwtUtil with asymmetric algorithm and public/private keys.
     *
     * @param algorithm the signature algorithm to use (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512)
     * @param publicKey the public key for token validation (Base64 encoded), can be null
     * @param privateKey the private key for token signing (Base64 encoded), can be null
     * @return JwtUtil instance
     * @throws IllegalArgumentException if the keys are invalid
     */
    public static JwtUtil withKeys(String algorithm, String publicKey, String privateKey) {
        SignatureAlgorithm alg = parseAlgorithm(algorithm);
        
        // Ensure it's not an HMAC algorithm
        if (isHmacAlgorithm(alg)) {
            throw new IllegalArgumentException("Use withSecret() factory method for HMAC algorithms");
        }
        
        return new JwtUtil(alg, null, publicKey, privateKey);
    }
    
    /**
     * Parse the signature algorithm string and return the corresponding SignatureAlgorithm enum.
     *
     * @param algorithm the algorithm string
     * @return the SignatureAlgorithm enum
     * @throws IllegalArgumentException if the algorithm is not supported
     */
    private static SignatureAlgorithm parseAlgorithm(String algorithm) {
        switch (algorithm.toUpperCase()) {
            // HMAC algorithms
            case "HS256":
                return SignatureAlgorithm.HS256;
            case "HS384":
                return SignatureAlgorithm.HS384;
            case "HS512":
                return SignatureAlgorithm.HS512;
                
            // RSA algorithms
            case "RS256":
                return SignatureAlgorithm.RS256;
            case "RS384":
                return SignatureAlgorithm.RS384;
            case "RS512":
                return SignatureAlgorithm.RS512;
                
            // ECDSA algorithms
            case "ES256":
                return SignatureAlgorithm.ES256;
            case "ES384":
                return SignatureAlgorithm.ES384;
            case "ES512":
                return SignatureAlgorithm.ES512;
                
            // RSASSA-PSS algorithms
            case "PS256":
                return SignatureAlgorithm.PS256;
            case "PS384":
                return SignatureAlgorithm.PS384;
            case "PS512":
                return SignatureAlgorithm.PS512;
                
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm + 
                    ". Supported algorithms are: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512");
        }
    }
    
    /**
     * Check if the algorithm is an HMAC algorithm.
     *
     * @param algorithm the algorithm to check
     * @return true if the algorithm is an HMAC algorithm, false otherwise
     */
    private static boolean isHmacAlgorithm(SignatureAlgorithm algorithm) {
        return algorithm == SignatureAlgorithm.HS256 || 
               algorithm == SignatureAlgorithm.HS384 || 
               algorithm == SignatureAlgorithm.HS512;
    }
    
    /**
     * Check if the algorithm is an RSA algorithm.
     *
     * @param algorithm the algorithm to check
     * @return true if the algorithm is an RSA algorithm, false otherwise
     */
    private static boolean isRsaAlgorithm(SignatureAlgorithm algorithm) {
        return algorithm == SignatureAlgorithm.RS256 || 
               algorithm == SignatureAlgorithm.RS384 || 
               algorithm == SignatureAlgorithm.RS512;
    }
    
    /**
     * Check if the algorithm is an RSASSA-PSS algorithm.
     *
     * @param algorithm the algorithm to check
     * @return true if the algorithm is an RSASSA-PSS algorithm, false otherwise
     */
    private static boolean isRsassaPssAlgorithm(SignatureAlgorithm algorithm) {
        return algorithm == SignatureAlgorithm.PS256 || 
               algorithm == SignatureAlgorithm.PS384 || 
               algorithm == SignatureAlgorithm.PS512;
    }
    
    /**
     * Check if the algorithm is an ECDSA algorithm.
     *
     * @param algorithm the algorithm to check
     * @return true if the algorithm is an ECDSA algorithm, false otherwise
     */
    private static boolean isEcdsaAlgorithm(SignatureAlgorithm algorithm) {
        return algorithm == SignatureAlgorithm.ES256 || 
               algorithm == SignatureAlgorithm.ES384 || 
               algorithm == SignatureAlgorithm.ES512;
    }
    
    /**
     * Generate an access token for the given user ID.
     *
     * @param userId the user ID to include in the token
     * @param expireMillis the expiration time in milliseconds
     * @return the generated access token
     */
    public String generateAccessToken(String userId, long expireMillis) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expireMillis);
        
        JwtBuilder builder = Jwts.builder()
                .setSubject(userId)
                .setIssuedAt(now)
                .setExpiration(expiryDate);
        
        // Sign with the appropriate key based on algorithm
        if (isHmacAlgorithm(algorithm)) {
            if (secretKey == null) {
                throw new IllegalStateException("Secret key is required for HMAC algorithms");
            }
            builder.signWith(secretKey, algorithm);
        } else {
            if (privateKey == null) {
                throw new IllegalStateException("Private key is required for asymmetric algorithms");
            }
            builder.signWith(privateKey, algorithm);
        }
        
        return builder.compact();
    }
    
    /**
     * Validate a token and get the claims.
     *
     * @param token the token to validate
     * @return the claims if valid, null otherwise
     */
    public Claims validateToken(String token) {
        try {
            if (isHmacAlgorithm(algorithm)) {
                if (secretKey == null) {
                    throw new IllegalStateException("Secret key is required for HMAC algorithms");
                }
                return Jwts.parserBuilder()
                        .setSigningKey(secretKey)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();
            } else {
                if (publicKey == null) {
                    throw new IllegalStateException("Public key is required for asymmetric algorithms");
                }
                return Jwts.parserBuilder()
                        .setSigningKey(publicKey)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();
            }
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
    public String getUserIdFromToken(String token) {
        Claims claims = validateToken(token);
        return claims != null ? claims.getSubject() : null;
    }
    
    /**
     * Check if a token is expired.
     *
     * @param token the token
     * @return true if expired, false otherwise
     */
    public boolean isTokenExpired(String token) {
        Claims claims = validateToken(token);
        return claims == null || claims.getExpiration().before(new Date());
    }
}