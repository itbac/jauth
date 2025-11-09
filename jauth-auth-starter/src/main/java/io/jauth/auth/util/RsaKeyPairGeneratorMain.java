package io.jauth.auth.util;

/**
 * Main class for generating RSA key pairs for JWT RS256/RS384/RS512 signing.
 * This class provides a convenient way to generate Base64 encoded RSA public and private keys
 * for JWT token signing with asymmetric encryption.
 */
public class RsaKeyPairGeneratorMain {
    
    public static void main(String[] args) {
        System.out.println("=== RSA Key Pair Generator ===");
        System.out.println("Generating RSA key pair for JWT signing...");
        System.out.println();
        
        // Generate RSA key pair
        RsaKeyPairGenerator.RsaKeyPair keyPair = RsaKeyPairGenerator.generateRsaKeyPair();
        
        System.out.println("Public Key (Base64):");
        System.out.println(keyPair.getPublicKey());
        System.out.println();
        System.out.println("Private Key (Base64):");
        System.out.println(keyPair.getPrivateKey());
        System.out.println();
        System.out.println("Key size: 2048 bits");
        System.out.println();
        System.out.println("You can use these keys in your jauth configuration:");
        System.out.println("jauth:");
        System.out.println("  client-type:");
        System.out.println("    web:");
        System.out.println("      access-token:");
        System.out.println("        algorithm: RS256");
        System.out.println("        public-key: \"" + keyPair.getPublicKey() + "\"");
        System.out.println("        private-key: \"" + keyPair.getPrivateKey() + "\"");
    }
}