package io.jauth.core.api;

import java.util.Map;

/**
 * Signature generator interface for refresh token security.
 * This interface allows different signature generation algorithms to be used.
 */
public interface SignatureGenerator {
    
    /**
     * Generate a signature based on the provided data.
     *
     * @param data the data to sign
     * @return the generated signature
     */
    String generateSignature(Map<String, String> data);
    
    /**
     * Validate a signature against the provided data.
     *
     * @param data the data that was signed
     * @param signature the signature to validate
     * @return true if the signature is valid, false otherwise
     */
    boolean validateSignature(Map<String, String> data, String signature);
}