package io.jauth.auth.service;

import io.jauth.core.api.SignatureGenerator;
import io.jauth.auth.config.AuthProperties;
import io.jauth.auth.util.SecretResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Advanced signature generator that supports multiple algorithms.
 * This implementation supports both hash-based algorithms (MD5, SHA-1, SHA-256, etc.)
 * and HMAC-based algorithms (HMAC-SHA256, HMAC-SHA512, etc.).
 */
@Component
public class AdvancedSignatureGenerator implements SignatureGenerator {
    
    private final AuthProperties authProperties;
    private final SecretResolver secretResolver;
    
    public AdvancedSignatureGenerator(AuthProperties authProperties, SecretResolver secretResolver) {
        this.authProperties = authProperties;
        this.secretResolver = secretResolver;
    }
    
    public AdvancedSignatureGenerator(AuthProperties authProperties) {
        this.authProperties = authProperties;
        this.secretResolver = null;
    }
    
    @Override
    public String generateSignature(Map<String, String> data) {
        // This method should be called with HttpServletRequest to determine the appropriate secret
        throw new UnsupportedOperationException("Use generateSignature(Map<String, String>, HttpServletRequest) instead");
    }
    
    @Override
    public boolean validateSignature(Map<String, String> data, String signature) {
        // This method should be called with HttpServletRequest to determine the appropriate secret
        throw new UnsupportedOperationException("Use validateSignature(Map<String, String>, String, HttpServletRequest) instead");
    }
    
    /**
     * Generate a signature based on the provided data and HTTP request.
     * This method uses the SecretResolver to determine the appropriate secret.
     *
     * @param data the data to sign
     * @param request the HTTP request used to determine the client and business type
     * @return the generated signature
     */
    public String generateSignature(Map<String, String> data, HttpServletRequest request) {
        if (secretResolver != null) {
            String secret = secretResolver.resolveSecret(request);
            return generateSignature(data, secret);
        } else {
            // Fallback to global secret if SecretResolver is not available
            return generateSignature(data, authProperties.getSecret());
        }
    }
    
    /**
     * Validate a signature against the provided data and HTTP request.
     * This method uses the SecretResolver to determine the appropriate secret.
     *
     * @param data the data that was signed
     * @param signature the signature to validate
     * @param request the HTTP request used to determine the client and business type
     * @return true if the signature is valid, false otherwise
     */
    public boolean validateSignature(Map<String, String> data, String signature, HttpServletRequest request) {
        if (secretResolver != null) {
            String secret = secretResolver.resolveSecret(request);
            return validateSignature(data, signature, secret);
        } else {
            // Fallback to global secret if SecretResolver is not available
            return validateSignature(data, signature, authProperties.getSecret());
        }
    }
    
    /**
     * Generate a signature based on the provided data and secret.
     *
     * @param data the data to sign
     * @param secret the secret key to use for signing
     * @return the generated signature
     */
    private String generateSignature(Map<String, String> data, String secret) {
        String algorithm = authProperties.getRefreshToken().getSecurity().getHashAlgorithm();
        
        // Check if it's an HMAC algorithm
        if (algorithm.startsWith("HMAC-")) {
            return generateHmacSignature(data, secret, algorithm.substring(5)); // Remove "HMAC-" prefix
        } else {
            // Use the standard hash algorithm
            return generateHashSignature(data, secret, algorithm);
        }
    }
    
    /**
     * Validate a signature against the provided data and secret.
     *
     * @param data the data that was signed
     * @param signature the signature to validate
     * @param secret the secret key used for signing
     * @return true if the signature is valid, false otherwise
     */
    private boolean validateSignature(Map<String, String> data, String signature, String secret) {
        String generatedSignature = generateSignature(data, secret);
        return generatedSignature.equals(signature);
    }
    
    /**
     * Generate a signature using HMAC algorithms.
     *
     * @param data the data to sign
     * @param secret the secret key
     * @param algorithm the hash algorithm to use (SHA256, SHA512, etc.)
     * @return the generated signature
     */
    private String generateHmacSignature(Map<String, String> data, String secret, String algorithm) {
        try {
            String algorithmName = "Hmac" + algorithm;
            Mac mac = Mac.getInstance(algorithmName);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), algorithmName);
            mac.init(secretKeySpec);
            
            // Sort the data to ensure consistent ordering
            SortedMap<String, String> sortedData = new TreeMap<>(data);
            
            // Append values of configured headers
            StringBuilder dataToSign = new StringBuilder();
            for (Map.Entry<String, String> entry : sortedData.entrySet()) {
                if (entry.getValue() != null) {
                    dataToSign.append(entry.getKey()).append("=").append(entry.getValue()).append("&");
                }
            }
            
            // Remove the trailing "&"
            if (dataToSign.length() > 0) {
                dataToSign.setLength(dataToSign.length() - 1);
            }
            
            byte[] signatureBytes = mac.doFinal(dataToSign.toString().getBytes(StandardCharsets.UTF_8));
            
            // Convert to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : signatureBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate HMAC signature: " + e.getMessage(), e);
        }
    }
    
    /**
     * Generate a signature using standard hash algorithms.
     *
     * @param data the data to sign
     * @param secret the secret key
     * @param algorithm the hash algorithm to use (MD5, SHA-1, SHA-256, etc.)
     * @return the generated signature
     */
    private String generateHashSignature(Map<String, String> data, String secret, String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            
            // Update with the secret first
            digest.update(secret.getBytes(StandardCharsets.UTF_8));
            
            // Sort the data to ensure consistent ordering
            SortedMap<String, String> sortedData = new TreeMap<>(data);
            
            // Append values of configured headers
            for (Map.Entry<String, String> entry : sortedData.entrySet()) {
                if (entry.getValue() != null) {
                    digest.update(entry.getKey().getBytes(StandardCharsets.UTF_8));
                    digest.update(entry.getValue().getBytes(StandardCharsets.UTF_8));
                }
            }
            
            // Convert the hash to a hex string
            byte[] hashBytes = digest.digest();
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hash algorithm not available: " + algorithm, e);
        }
    }
}