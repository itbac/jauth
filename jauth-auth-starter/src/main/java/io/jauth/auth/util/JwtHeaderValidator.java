package io.jauth.auth.util;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

public class JwtHeaderValidator {

    private static final ObjectMapper mapper = new ObjectMapper();

    // 手动提取并校验 alg
    public static String getAndVerifyAlg(String jwt, String expectedAlg) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid JWT format");
        }

        // 解码头部
        String headerJson = new String(
            Base64.getUrlDecoder().decode(padBase64(parts[0])), 
            StandardCharsets.UTF_8
        );

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> header = mapper.readValue(headerJson, Map.class);
            String alg = (String) header.get("alg");

            if (alg == null) {
                throw new SecurityException("Missing 'alg' in JWT header");
            }
            if (!expectedAlg.equals(alg)) {
                throw new SecurityException("Unexpected alg: " + alg + ", expected: " + expectedAlg);
            }
            return alg;
        } catch (Exception e) {
            throw new SecurityException("Failed to parse JWT header", e);
        }
    }

    // Base64 URL 解码需要补 '='
    private static String padBase64(String base64Url) {
        String s = base64Url;
        switch (s.length() % 4) {
            case 0: break;
            case 2: s += "=="; break;
            case 3: s += "="; break;
            default: throw new IllegalArgumentException("Invalid base64 string");
        }
        return s;
    }
}