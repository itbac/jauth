package io.jauth.demo.auth.api;

import dev.paseto.jpaseto.Paseto;
import dev.paseto.jpaseto.Pasetos;
import dev.paseto.jpaseto.lang.Keys;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * PASETO加密验签示例类
 * 
 * 本示例演示了如何使用PASETO库进行令牌的创建、加密和验证
 * PASETO (Platform-Agnostic SEcurity TOkens) 是一种现代的安全令牌格式
 * 它旨在替代JWT，提供更安全、更简单的实现方式
 */
public class PasetoExample {
    
    // 密钥（在实际应用中应该安全存储）
    private static final SecretKey SECRET_KEY = Keys.secretKey();
    
    /**
     * 创建并加密PASETO令牌（local模式，对称加密）
     * 
     * @param userId 用户ID
     * @param expiration 过期时间（秒）
     * @return 加密后的PASETO令牌
     */
    public String createLocalToken(String userId, long expiration) {
        try {
            Instant now = Instant.now();
            
            // 使用PASETO加密令牌（local模式）
            // 使用V1版本，这是JPaseto支持的版本
            String token = Pasetos.V1.LOCAL.builder()
                    .setSharedSecret(SECRET_KEY)
                    .setIssuedAt(now)
                    .setExpiration(now.plusSeconds(expiration))
                    .setSubject(userId)
                    .setAudience("jauth-demo")
                    .setIssuer("https://jauth.example.com/")
                    .claim("custom-data", "example-value")
                    .compact();
            
            return token;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create PASETO token", e);
        }
    }
    
    /**
     * 验证PASETO令牌（local模式，对称加密）
     * 
     * @param token PASETO令牌
     * @return 令牌中的声明信息，如果验证失败则返回null
     */
    public Map<String, Object> validateLocalToken(String token) {
        try {
            // 解密并验证令牌
            Paseto result = Pasetos.parserBuilder()
                    .setSharedSecret(SECRET_KEY)
                    .requireAudience("jauth-demo")
                    .build()
                    .parse(token);
            
            // 获取声明
            Map<String, Object> claims = new HashMap<>();
            claims.put("user_id", result.getClaims().getSubject());
            claims.put("iat", result.getClaims().getIssuedAt());
            claims.put("exp", result.getClaims().getExpiration());
            claims.put("aud", result.getClaims().getAudience());
            claims.put("iss", result.getClaims().getIssuer());
            claims.put("custom-data", result.getClaims().get("custom-data"));
            
            return claims;
        } catch (Exception e) {
            System.err.println("Failed to validate PASETO token: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * 主方法，用于演示PASETO的使用
     */
    public static void main(String[] args) {
        PasetoExample example = new PasetoExample();
        
        System.out.println("=== PASETO 加密验签示例 ===");
        
        // 创建local令牌（对称加密）
        String userId = "user123";
        long expiration = 3600; // 1小时
        String localToken = example.createLocalToken(userId, expiration);
        
        System.out.println("创建的local令牌:");
        System.out.println(localToken);
        System.out.println();
        
        // 验证local令牌
        Map<String, Object> localClaims = example.validateLocalToken(localToken);
        
        if (localClaims != null) {
            System.out.println("local令牌验证成功!");
            System.out.println("用户ID: " + localClaims.get("user_id"));
            System.out.println("签发时间: " + localClaims.get("iat"));
            System.out.println("过期时间: " + localClaims.get("exp"));
            System.out.println("受众: " + localClaims.get("aud"));
            System.out.println("发行方: " + localClaims.get("iss"));
            System.out.println("自定义数据: " + localClaims.get("custom-data"));
        } else {
            System.out.println("local令牌验证失败!");
        }
        
        System.out.println();
        
        // 演示验证失败的情况
        System.out.println("=== 演示验证失败的情况 ===");
        String invalidToken = localToken + "invalid";
        Map<String, Object> invalidClaims = example.validateLocalToken(invalidToken);
        
        if (invalidClaims == null) {
            System.out.println("无效令牌验证失败，符合预期");
        }
    }
}