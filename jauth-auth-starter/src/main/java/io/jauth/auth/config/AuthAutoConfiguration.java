/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.jauth.auth.config;

import io.jauth.auth.service.AdvancedSignatureGenerator;
import io.jauth.auth.service.DefaultAuthUtils;
import io.jauth.auth.service.DefaultRefreshTokenService;
import io.jauth.auth.service.DefaultTokenGenerator;
import io.jauth.auth.util.SecretResolver;
import io.jauth.core.api.AuthUtils;
import io.jauth.core.api.RefreshTokenService;
import io.jauth.core.api.SignatureGenerator;
import io.jauth.core.api.TokenGenerator;
import io.jauth.core.util.JwtUtil;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;

/**
 * Auto-configuration for the authentication module.
 * This configuration class provides beans for JWT utility and token generation.
 */
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthAutoConfiguration {

    /**
     * Create a JwtUtil bean using the configured secret.
     *
     * @param authProperties the authentication properties
     * @return a JwtUtil instance
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtUtil jwtUtil(AuthProperties authProperties) {
        String algorithm = authProperties.getAccessToken().getAlgorithm();
        
        if ("RS256".equals(algorithm)) {
            // For RS256, use public and private keys
            String publicKey = authProperties.getAccessToken().getPublicKey();
            String privateKey = authProperties.getAccessToken().getPrivateKey();
            return JwtUtil.withKeys(algorithm, publicKey, privateKey);
        } else {
            // For HMAC algorithms, use secret
            String secret = authProperties.getAccessToken().getSecret();
            // Ensure the secret is at least 32 characters long
            if (secret.length() < 32) {
                throw new IllegalArgumentException("Secret must be at least 32 characters long for HMAC algorithms");
            }
            return JwtUtil.withSecret(algorithm, secret);
        }
    }

    /**
     * Create a DefaultTokenGenerator bean.
     *
     * @param jwtUtil the JWT utility
     * @param authProperties the authentication properties
     * @return a DefaultTokenGenerator instance
     */
    @Bean
    @ConditionalOnMissingBean
    public DefaultTokenGenerator defaultTokenGenerator(JwtUtil jwtUtil, AuthProperties authProperties) {
        return new DefaultTokenGenerator(jwtUtil, authProperties);
    }
    
    /**
     * Create a TokenGenerator bean.
     *
     * @param defaultTokenGenerator the default token generator
     * @return a TokenGenerator instance
     */
    @Bean
    @ConditionalOnMissingBean
    public TokenGenerator tokenGenerator(DefaultTokenGenerator defaultTokenGenerator) {
        return defaultTokenGenerator;
    }
    
    /**
     * Create a DefaultRefreshTokenService bean.
     *
     * @param redisTemplate the Redis template for string operations
     * @param authProperties the authentication properties
     * @param signatureGenerator the signature generator
     * @param secretResolver the secret resolver
     * @return a DefaultRefreshTokenService instance
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean(RedisTemplate.class)
    public DefaultRefreshTokenService defaultRefreshTokenService(
            RedisTemplate<String, String> redisTemplate,
            AuthProperties authProperties,
            SignatureGenerator signatureGenerator,
            SecretResolver secretResolver) {
        return new DefaultRefreshTokenService(redisTemplate, authProperties, signatureGenerator, secretResolver);
    }
    
    /**
     * Create a RefreshTokenService bean.
     *
     * @param defaultRefreshTokenService the default refresh token service
     * @return a RefreshTokenService instance
     */
    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenService refreshTokenService(DefaultRefreshTokenService defaultRefreshTokenService) {
        return defaultRefreshTokenService;
    }
    
    /**
     * Create an AdvancedSignatureGenerator bean.
     *
     * @param authProperties the authentication properties
     * @return an AdvancedSignatureGenerator instance
     */
    @Bean
    @ConditionalOnMissingBean
    public SignatureGenerator signatureGenerator(AuthProperties authProperties) {
        return new AdvancedSignatureGenerator(authProperties);
    }
    
    /**
     * Create a DefaultAuthUtils bean.
     *
     * @param tokenGenerator the token generator
     * @param authProperties the authentication properties
     * @param refreshTokenService the refresh token service
     * @return a DefaultAuthUtils instance
     */
    @Bean
    @ConditionalOnMissingBean
    public DefaultAuthUtils defaultAuthUtils(TokenGenerator tokenGenerator, AuthProperties authProperties,
                                             RefreshTokenService refreshTokenService) {
        return new DefaultAuthUtils(tokenGenerator, authProperties, refreshTokenService);
    }
    
    /**
     * Create a SecretResolver bean.
     *
     * @param authProperties the authentication properties
     * @return a SecretResolver instance
     */
    @Bean
    @ConditionalOnMissingBean
    public SecretResolver secretResolver(AuthProperties authProperties) {
        return new SecretResolver(authProperties);
    }
    
    /**
     * Create an AuthUtils bean.
     *
     * @param defaultAuthUtils the DefaultAuthUtils instance
     * @return an AuthUtils instance
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthUtils authUtils(DefaultAuthUtils defaultAuthUtils) {
        return defaultAuthUtils;
    }
}