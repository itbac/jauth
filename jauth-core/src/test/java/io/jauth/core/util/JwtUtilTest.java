package io.jauth.core.util;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class JwtUtilTest {

    @Test
    public void testJwtUtilWithHmacKeys() {
        try {
            // 创建JwtUtil实例，使用HMAC算法
            String secret = "thisisaverylongsecretkeythatmeetsminimumlengthrequirement";
            JwtUtil jwtUtil = JwtUtil.withSecret("HS256", secret);
            
            // 生成访问令牌
            String userId = "testUser123";
            long expireMillis = 3600000; // 1小时
            String token = jwtUtil.generateAccessToken(userId, expireMillis);
            
            // 验证令牌不为空
            assertNotNull(token, "生成的令牌不应为空");
            assertFalse(token.isEmpty(), "生成的令牌不应为空字符串");
            
            // 验证可以从令牌中提取用户ID
            String extractedUserId = jwtUtil.getUserIdFromToken(token);
            assertEquals(userId, extractedUserId, "提取的用户ID应与原始用户ID匹配");
            
            // 验证令牌未过期
            assertFalse(jwtUtil.isTokenExpired(token), "新生成的令牌不应过期");
            
            System.out.println("JWT Token with HMAC: " + token);
            System.out.println("User ID: " + extractedUserId);
        } catch (Exception e) {
            fail("测试过程中发生异常: " + e.getMessage());
        }
    }
    
    @Test
    public void testJwtUtilWithRsaKeys() {
        // 生成RSA密钥对用于测试
        java.security.KeyPairGenerator keyGen;
        try {
            keyGen = java.security.KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            java.security.KeyPair keyPair = keyGen.generateKeyPair();
            
            // 将密钥转换为Base64编码的字符串
            String publicKey = java.util.Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKey = java.util.Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            
            // 创建JwtUtil实例，使用RSA算法
            JwtUtil jwtUtil = JwtUtil.withKeys("RS256", publicKey, privateKey);
            
            // 生成访问令牌
            String userId = "testUser123";
            long expireMillis = 3600000; // 1小时
            String token = jwtUtil.generateAccessToken(userId, expireMillis);
            
            // 验证令牌不为空
            assertNotNull(token, "生成的令牌不应为空");
            assertFalse(token.isEmpty(), "生成的令牌不应为空字符串");
            
            // 验证可以从令牌中提取用户ID
            String extractedUserId = jwtUtil.getUserIdFromToken(token);
            assertEquals(userId, extractedUserId, "提取的用户ID应与原始用户ID匹配");
            
            // 验证令牌未过期
            assertFalse(jwtUtil.isTokenExpired(token), "新生成的令牌不应过期");
            
            System.out.println("JWT Token with RSA: " + token);
            System.out.println("User ID: " + extractedUserId);
        } catch (Exception e) {
            fail("测试过程中发生异常: " + e.getMessage());
        }
    }
    
    @Test
    public void testJwtUtilWithSpecificAlgorithm() {
        // 生成RSA密钥对用于测试
        java.security.KeyPairGenerator keyGen;
        try {
            keyGen = java.security.KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            java.security.KeyPair keyPair = keyGen.generateKeyPair();
            
            // 将密钥转换为Base64编码的字符串
            String publicKey = java.util.Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKey = java.util.Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            
            // 使用特定算法创建JwtUtil实例
            JwtUtil jwtUtil = JwtUtil.withKeys("RS512", publicKey, privateKey);
            
            // 生成访问令牌
            String userId = "testUser456";
            long expireMillis = 3600000; // 1小时
            String token = jwtUtil.generateAccessToken(userId, expireMillis);
            
            // 验证令牌不为空
            assertNotNull(token, "生成的令牌不应为空");
            assertFalse(token.isEmpty(), "生成的令牌不应为空字符串");
            
            // 验证可以从令牌中提取用户ID
            String extractedUserId = jwtUtil.getUserIdFromToken(token);
            assertEquals(userId, extractedUserId, "提取的用户ID应与原始用户ID匹配");
            
            System.out.println("JWT Token with RS512: " + token);
            System.out.println("User ID: " + extractedUserId);
        } catch (Exception e) {
            fail("测试过程中发生异常: " + e.getMessage());
        }
    }
    
    @Test
    public void testJwtUtilWithPublicKeyOnly() {
        // 生成RSA密钥对用于测试
        java.security.KeyPairGenerator keyGen;
        try {
            keyGen = java.security.KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            java.security.KeyPair keyPair = keyGen.generateKeyPair();
            
            // 将公钥转换为Base64编码的字符串
            String publicKey = java.util.Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            
            // 使用公钥创建JwtUtil实例（使用RSA算法）
            JwtUtil jwtUtil = JwtUtil.withPublicKey("RS256", publicKey);
            
            // 尝试生成访问令牌应该失败，因为没有私钥
            String userId = "testUser789";
            long expireMillis = 3600000; // 1小时
            
            // 验证生成令牌时抛出异常
            Exception exception = assertThrows(IllegalStateException.class, () -> {
                jwtUtil.generateAccessToken(userId, expireMillis);
            });
            
            assertEquals("Private key is required for asymmetric algorithms", exception.getMessage());
            
            System.out.println("验证了只有公钥时无法生成令牌");
        } catch (Exception e) {
            fail("测试过程中发生异常: " + e.getMessage());
        }
    }
    
    @Test
    public void testJwtUtilWithPublicKeyOnlyWithAlgorithm() {
        // 生成RSA密钥对用于测试
        java.security.KeyPairGenerator keyGen;
        try {
            keyGen = java.security.KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            java.security.KeyPair keyPair = keyGen.generateKeyPair();
            
            // 将公钥转换为Base64编码的字符串
            String publicKey = java.util.Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            
            // 使用公钥创建JwtUtil实例（指定算法）
            JwtUtil jwtUtil = JwtUtil.withPublicKey("RS384", publicKey);
            
            // 尝试生成访问令牌应该失败，因为没有私钥
            String userId = "testUser101";
            long expireMillis = 3600000; // 1小时
            
            // 验证生成令牌时抛出异常
            Exception exception = assertThrows(IllegalStateException.class, () -> {
                jwtUtil.generateAccessToken(userId, expireMillis);
            });
            
            assertEquals("Private key is required for asymmetric algorithms", exception.getMessage());
            
            System.out.println("验证了只有公钥时无法生成令牌（使用RS384算法）");
        } catch (Exception e) {
            fail("测试过程中发生异常: " + e.getMessage());
        }
    }
    
    @Test
    public void testJwtUtilWithPrivateKeyOnly() {
        // 生成RSA密钥对用于测试
        java.security.KeyPairGenerator keyGen;
        try {
            keyGen = java.security.KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            java.security.KeyPair keyPair = keyGen.generateKeyPair();
            
            // 将私钥转换为Base64编码的字符串
            String privateKey = java.util.Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            
            // 使用私钥创建JwtUtil实例
            JwtUtil jwtUtil = JwtUtil.withKeys("RS256", null, privateKey);
            
            // 生成访问令牌
            String userId = "testUser987";
            long expireMillis = 3600000; // 1小时
            String token = jwtUtil.generateAccessToken(userId, expireMillis);
            
            // 验证令牌不为空
            assertNotNull(token, "生成的令牌不应为空");
            assertFalse(token.isEmpty(), "生成的令牌不应为空字符串");
            
            // 尝试验证令牌应该返回null，因为没有公钥
            String extractedUserId = jwtUtil.getUserIdFromToken(token);
            assertNull(extractedUserId, "在没有公钥的情况下应返回null");
            
            // 尝试检查令牌是否过期也应该返回true，因为没有公钥
            assertTrue(jwtUtil.isTokenExpired(token), "在没有公钥的情况下应返回true");
            
            System.out.println("JWT Token with private key only: " + token);
            System.out.println("验证了只有私钥时无法验证令牌");
        } catch (Exception e) {
            fail("测试过程中发生异常: " + e.getMessage());
        }
    }
    
    @Test
    public void testJwtUtilWithEcdsaKeys() {
        // 生成ECDSA密钥对用于测试
        try {
            java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256); // ES256
            java.security.KeyPair keyPair = keyGen.generateKeyPair();
            
            // 将密钥转换为Base64编码的字符串
            String publicKey = java.util.Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            String privateKey = java.util.Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
            
            // 创建JwtUtil实例，使用ECDSA算法
            JwtUtil jwtUtil = JwtUtil.withKeys("ES256", publicKey, privateKey);
            
            // 生成访问令牌
            String userId = "testUserECDSA";
            long expireMillis = 3600000; // 1小时
            String token = jwtUtil.generateAccessToken(userId, expireMillis);
            
            // 验证令牌不为空
            assertNotNull(token, "生成的令牌不应为空");
            assertFalse(token.isEmpty(), "生成的令牌不应为空字符串");
            
            // 验证可以从令牌中提取用户ID
            String extractedUserId = jwtUtil.getUserIdFromToken(token);
            assertEquals(userId, extractedUserId, "提取的用户ID应与原始用户ID匹配");
            
            // 验证令牌未过期
            assertFalse(jwtUtil.isTokenExpired(token), "新生成的令牌不应过期");
            
            System.out.println("JWT Token with ECDSA: " + token);
            System.out.println("User ID: " + extractedUserId);
        } catch (Exception e) {
            fail("测试过程中发生异常: " + e.getMessage());
        }
    }
    
    @Test
    public void testJwtUtilWithEcdsaPublicKeyOnly() {
        // 生成ECDSA密钥对用于测试
        try {
            java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("EC");
            java.security.spec.ECGenParameterSpec ecSpec = new java.security.spec.ECGenParameterSpec("secp256r1");
            keyGen.initialize(ecSpec);
            java.security.KeyPair keyPair = keyGen.generateKeyPair();
            
            // 将公钥转换为Base64编码的字符串
            String publicKey = java.util.Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            
            // 使用公钥创建JwtUtil实例（使用默认算法ES256）
            JwtUtil jwtUtil = JwtUtil.withPublicKey(publicKey);
            
            // 尝试生成访问令牌应该失败，因为没有私钥
            String userId = "testUserECDSA2";
            long expireMillis = 3600000; // 1小时
            
            // 验证生成令牌时抛出异常
            Exception exception = assertThrows(IllegalStateException.class, () -> {
                jwtUtil.generateAccessToken(userId, expireMillis);
            });
            
            assertEquals("Private key is required for asymmetric algorithms", exception.getMessage());
            
            System.out.println("验证了只有公钥时无法生成令牌（使用ES256算法）");
        } catch (Exception e) {
            fail("测试过程中发生异常: " + e.getMessage());
        }
    }
}