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

package io.jauth.resource;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

/**
 * Auto-configuration class for JAuth resource server.
 * This configuration class sets up the JWT authentication filter
 * and security configuration for resource servers.
 */
@Configuration
@ConditionalOnWebApplication
@EnableConfigurationProperties(ResourceSecurityProperties.class)
public class ResourceAutoConfiguration {



    /**
     * Create a JwtAuthenticationFilter bean for validating JWT tokens.
     *
     * @param resourceSecurityProperties the resource security properties
     * @return a JwtAuthenticationFilter instance
     */
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(
                                                          ResourceSecurityProperties resourceSecurityProperties) {
        return new JwtAuthenticationFilter(resourceSecurityProperties);
    }

    /**
     * Create a RedisTemplate for string operations.
     *
     * @param redisConnectionFactory the Redis connection factory
     * @return a RedisTemplate for string operations
     */
    @Bean
    public RedisTemplate<String, String> redisTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, String> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new StringRedisSerializer());
        return template;
    }

    /**
     * Create a RedisTemplate for long operations.
     *
     * @param redisConnectionFactory the Redis connection factory
     * @return a RedisTemplate for long operations
     */
    @Bean
    public RedisTemplate<String, Long> redisLongTemplate(RedisConnectionFactory redisConnectionFactory) {
        RedisTemplate<String, Long> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        return template;
    }
}