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

import io.jauth.auth.service.*;
import io.jauth.core.api.*;
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
            SignatureGenerator signatureGenerator) {
        return new DefaultRefreshTokenService(redisTemplate, authProperties, signatureGenerator);
    }
    @Bean
    @ConditionalOnMissingBean
    public AccessTokenService accessTokenService(AuthProperties authProperties){
        return new DefaultAccessTokenService(authProperties);
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
     * @param tokenGenerator      the token generator
     * @param authProperties      the authentication properties
     * @param refreshTokenService the refresh token service
     * @return a DefaultAuthUtils instance
     */
    @Bean
    @ConditionalOnMissingBean
    public DefaultAuthUtils defaultAuthUtils(AuthProperties authProperties,
                                             AccessTokenService accessTokenService,
                                             RefreshTokenService refreshTokenService) {
        return new DefaultAuthUtils(authProperties, accessTokenService, refreshTokenService);
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