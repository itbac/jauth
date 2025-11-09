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

package io.jauth.core.api;

/**
 * Interface for token generation.
 * This interface provides methods for generating access and refresh tokens.
 */
public interface TokenGenerator {
    
    /**
     * Generate an access token for the given user ID.
     *
     * @param userId the user ID to include in the token
     * @return the generated access token
     */
    String generateAccessToken(String userId);
    
    /**
     * Generate a refresh token.
     *
     * @return the generated refresh token
     */
    String generateRefreshToken();
}