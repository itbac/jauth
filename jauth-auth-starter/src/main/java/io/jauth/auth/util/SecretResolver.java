package io.jauth.auth.util;

import io.jauth.auth.config.AuthProperties;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * Secret resolver that determines which secret to use based on client type and business type.
 * This class supports different secrets for different clients (web, app, mini-program) 
 * and business types (B-end, C-end).
 */
@Component
public class SecretResolver {
    
    private final AuthProperties authProperties;
    
    public SecretResolver(AuthProperties authProperties) {
        this.authProperties = authProperties;
    }
    
    /**
     * Resolve the secret to use based on the HTTP request.
     * This method analyzes the request to determine client type and business type,
     * then returns the appropriate secret.
     *
     * @param request the HTTP request
     * @return the resolved secret
     */
    public String resolveSecret(HttpServletRequest request) {
        // First, try to determine client type
        String clientType = determineClientType(request);
        
        // Then, try to determine business type
        String businessType = determineBusinessType(request);
        
        // Try to get client-specific secret
        if (clientType != null && authProperties.getClientSecrets().containsKey(clientType)) {
            return authProperties.getClientSecrets().get(clientType);
        }
        
        // Try to get business-specific secret
        if (businessType != null && authProperties.getBusinessSecrets().containsKey(businessType)) {
            return authProperties.getBusinessSecrets().get(businessType);
        }
        
        // Fall back to global secret
        return authProperties.getSecret();
    }
    
    /**
     * Determine client type based on the HTTP request.
     * This method analyzes User-Agent and custom headers to identify the client.
     *
     * @param request the HTTP request
     * @return the client type (web, app, mini-program) or null if not determinable
     */
    private String determineClientType(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        String clientHeader = request.getHeader("X-Client-Type");
        
        // If client type is explicitly specified in header, use it
        if (clientHeader != null && !clientHeader.isEmpty()) {
            return clientHeader.toLowerCase();
        }
        
        // Analyze User-Agent to determine client type
        if (userAgent != null) {
            userAgent = userAgent.toLowerCase();
            
            // Check for mini-program clients
            if (userAgent.contains("miniprogram") || userAgent.contains("micromessenger")) {
                return "mini-program";
            }
            
            // Check for mobile app clients
            if (userAgent.contains("mobile") || userAgent.contains("android") || userAgent.contains("iphone")) {
                return "app";
            }
            
            // Assume web client for everything else
            return "web";
        }
        
        // Default to web if we can't determine
        return "web";
    }
    
    /**
     * Determine business type based on the HTTP request.
     * This method analyzes custom headers to identify the business type.
     *
     * @param request the HTTP request
     * @return the business type (b-end, c-end) or null if not determinable
     */
    private String determineBusinessType(HttpServletRequest request) {
        String businessHeader = request.getHeader("X-Business-Type");
        
        if (businessHeader != null && !businessHeader.isEmpty()) {
            return businessHeader.toLowerCase();
        }
        
        // Default to null if not specified
        return null;
    }
}