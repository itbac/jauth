package io.jauth.core.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
/**
 * Ed25519 秘钥生成器
 */
public class Ed25519KeyGenerator {


    public static KeyPair generateKeyPair() throws Exception {
        Provider bc = Security.getProvider("BC");
        if (null == bc) {
            Security.addProvider(new BouncyCastleProvider());
        }
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
        return kpg.generateKeyPair();
    }

    public static PrivateKey loadPrivateKey(String privateKeyBase64) throws Exception {
        Provider bc = Security.getProvider("BC");
        if (null == bc) {
            Security.addProvider(new BouncyCastleProvider());
        }
        byte[] privBytes = Base64.getDecoder().decode(privateKeyBase64);
        KeyFactory kf = KeyFactory.getInstance("Ed25519", "BC");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
    }

    public static PublicKey loadPublicKey(String publicKeyBase64) throws Exception {
        Provider bc = Security.getProvider("BC");
        if (null == bc) {
            Security.addProvider(new BouncyCastleProvider());
        }
        byte[] pubBytes = Base64.getDecoder().decode(publicKeyBase64);
        KeyFactory kf = KeyFactory.getInstance("Ed25519", "BC");
        return kf.generatePublic(new X509EncodedKeySpec(pubBytes));
    }

    public static void main(String[] args) throws Exception {

        KeyPair keyPair = generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // 打印 Base64 编码（便于存储或配置）
        System.out.println("Private Key (Base64): " + 
            Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("Public Key (Base64): " + 
            Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        /**
         * Private Key (Base64): MFECAQEwBQYDK2VwBCIEIFsTNCv8bP5oNLTYBFhqpnw7nvtTb4F83TWnyYzuYfDNgSEAGNyU8Z/d0nZq0kE341se9d7t9yPl6XWwp8rRRg5OGb8=
         * Public Key (Base64): MCowBQYDK2VwAyEAGNyU8Z/d0nZq0kE341se9d7t9yPl6XWwp8rRRg5OGb8=
         *
         */
    }
}