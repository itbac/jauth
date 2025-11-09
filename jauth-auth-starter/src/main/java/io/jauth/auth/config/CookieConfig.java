package io.jauth.auth.config;

/**
 * Cookie configuration properties.
 * This class holds configuration values for cookie settings.
 */
public class CookieConfig {
    /**
     * The SameSite attribute for cookies. Can be "Strict", "Lax", or "None".
     * Default is "Lax" for a good balance between security and usability.
     */
    private String sameSite = "Lax";
    
    /**
     * Whether to set the Secure flag on cookies. Default is true.
     */
    private boolean secure = true;
    
    /**
     * Get the SameSite attribute for cookies.
     *
     * @return the SameSite attribute value
     */
    public String getSameSite() {
        return sameSite;
    }
    
    /**
     * Set the SameSite attribute for cookies.
     * Must be one of "Strict", "Lax", or "None".
     *
     * @param sameSite the SameSite attribute value to set
     */
    public void setSameSite(String sameSite) {
        // Validate the value
        if (!"Strict".equals(sameSite) && 
            !"Lax".equals(sameSite) && 
            !"None".equals(sameSite)) {
            throw new IllegalArgumentException("Invalid SameSite value: " + sameSite + 
                ". Must be one of: Strict, Lax, None");
        }
        this.sameSite = sameSite;
    }
    
    /**
     * Get whether to set the Secure flag on cookies.
     *
     * @return true if the Secure flag should be set, false otherwise
     */
    public boolean isSecure() {
        return secure;
    }
    
    /**
     * Set whether to set the Secure flag on cookies.
     *
     * @param secure true to set the Secure flag, false otherwise
     */
    public void setSecure(boolean secure) {
        this.secure = secure;
    }
}