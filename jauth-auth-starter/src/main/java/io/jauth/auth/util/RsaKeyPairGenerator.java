package io.jauth.auth.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Utility class for generating RSA key pairs for JWT RS256/RS384/RS512 signing.
 * This class provides methods to generate Base64 encoded RSA public and private keys
 * for JWT token signing with asymmetric encryption.
 */
public class RsaKeyPairGenerator {

    private static final int RSA_KEY_SIZE = 2048;

    /**
     * Generate an RSA key pair and return the Base64 encoded public and private keys.
     *
     * @return RsaKeyPair containing Base64 encoded public and private keys
     */
    public static RsaKeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(RSA_KEY_SIZE);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

            return new RsaKeyPair(publicKey, privateKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }

    /**
     * Simple data class to hold RSA public and private keys.
     */
    public static class RsaKeyPair {
        private final String publicKey;
        private final String privateKey;

        public RsaKeyPair(String publicKey, String privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public String getPrivateKey() {
            return privateKey;
        }
    }
}