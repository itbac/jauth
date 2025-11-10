package io.jauth.auth;

import io.jauth.core.util.Ed25519KeyGenerator;
import io.jauth.auth.util.JwtHeaderValidator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

public class Ed25519JwtTokenTest {

    public static void main(String[] args) throws Exception {

        long now = System.currentTimeMillis();
        PrivateKey privateKey = Ed25519KeyGenerator.loadPrivateKey("MFECAQEwBQYDK2VwBCIEIFsTNCv8bP5oNLTYBFhqpnw7nvtTb4F83TWnyYzuYfDNgSEAGNyU8Z/d0nZq0kE341se9d7t9yPl6XWwp8rRRg5OGb8=");

        PublicKey publicKey = Ed25519KeyGenerator.loadPublicKey("MCowBQYDK2VwAyEAGNyU8Z/d0nZq0kE341se9d7t9yPl6XWwp8rRRg5OGb8=");

        String issuer = "88888";
        String audience = "toC";
        String token = Jwts.builder()
                .setSubject("123456") // 载荷：用户ID（非敏感）
                .setIssuer(issuer)
                .setAudience(audience)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now +1000*10000))
                .signWith(privateKey, Jwts.SIG.EdDSA) // 最新版正确用法：Jwts.SIG.Ed25519
                .compact();
// eyJhbGciOiJOT05FIn0=.eyJzdWIiOiIxMjM0NTYiLCJpc3MiOiI4ODg4OCIsImF1ZCI6InRvQyIsImlhdCI6MTc2Mjc1OTA0OSwiZXhwIjoxNzYzMDE0NjA0fQ.2-sP0qlKz2Nwx5RZTDn9_8Q1cof_iKscn3-wEdXJJALA_IeVfx5qBGSQTwcpRkgxQ5a2OP9e17P0N1TeTH0GCQ
//alg=EdDSA
        System.out.println("token=" + token);

        //测试篡改

//        String[] parts = token.split("\\.");
//        //篡改 {"alg":"NONE"} ,{"alg":"ES256"}
//        parts[0] = "eyJhbGciOiJFUzI1NiJ9";
//        token = String.join("\\.", parts);
//        System.out.println("篡改token=" + token);

        String alg = JwtHeaderValidator.getAndVerifyAlg(token, "EdDSA");
        System.out.println("alg=" + alg);

        //测试过期
//        Thread.sleep(1500);

        //验签
        Jws<Claims> claimsJws = Jwts.parser()
                .verifyWith(publicKey)
                .requireIssuer(issuer)
                .requireAudience(audience)
                .build()
                .parseSignedClaims(token);

        JwsHeader header = claimsJws.getHeader();
        Claims payload = claimsJws.getPayload();

        System.out.println("header=" + header);
        System.out.println("payload=" + payload);
        System.out.println("Subject=" + payload.getSubject());
        System.out.println("Issuer=" + payload.getIssuer());
        System.out.println("Audience=" + payload.getAudience());
    }
}