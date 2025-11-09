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

package io.jauth.core.dto;

/**
 * Response object for login operations.
 * This class contains the access token, refresh token, login time, and access token expiration time.
 */
public class LoginResponse {
    private String accessToken;
    private String refreshToken;
    private long loginTime;
    private int accessTokenExpiresIn; // Access token expiration time in seconds
    
    /**
     * Default constructor.
     */
    public LoginResponse() {
    }
    
    /**
     * Constructor with all parameters.
     *
     * @param accessToken the access token
     * @param refreshToken the refresh token
     * @param loginTime the login time
     * @param accessTokenExpiresIn the access token expiration time in seconds
     */
    public LoginResponse(String accessToken, String refreshToken, long loginTime, int accessTokenExpiresIn) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.loginTime = loginTime;
        this.accessTokenExpiresIn = accessTokenExpiresIn;
    }
    
    /**
     * Get the access token.
     *
     * @return the access token
     */
    public String getAccessToken() {
        return accessToken;
    }
    
    /**
     * Set the access token.
     *
     * @param accessToken the access token to set
     */
    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
    
    /**
     * Get the refresh token.
     *
     * @return the refresh token
     */
    public String getRefreshToken() {
        return refreshToken;
    }
    
    /**
     * Set the refresh token.
     *
     * @param refreshToken the refresh token to set
     */
    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }
    
    /**
     * Get the login time.
     *
     * @return the login time
     */
    public long getLoginTime() {
        return loginTime;
    }
    
    /**
     * Set the login time.
     *
     * @param loginTime the login time to set
     */
    public void setLoginTime(long loginTime) {
        this.loginTime = loginTime;
    }
    
    /**
     * Get the access token expiration time in seconds.
     *
     * @return the access token expiration time in seconds
     */
    public int getAccessTokenExpiresIn() {
        return accessTokenExpiresIn;
    }
    
    /**
     * Set the access token expiration time in seconds.
     *
     * @param accessTokenExpiresIn the access token expiration time in seconds to set
     */
    public void setAccessTokenExpiresIn(int accessTokenExpiresIn) {
        this.accessTokenExpiresIn = accessTokenExpiresIn;
    }
}