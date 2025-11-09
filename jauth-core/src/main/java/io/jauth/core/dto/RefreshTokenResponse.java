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
 * Response object for refresh token operations.
 * This class contains the result of the refresh token operation and the new tokens if successful.
 */
public class RefreshTokenResponse {
    // Result constants
    public static final String RESULT_SUCCESS = "success";
    public static final String RESULT_INVALID_TOKEN = "invalid_token";
    public static final String RESULT_MISSING_TOKEN = "missing_token";
    public static final String RESULT_INTERNAL_ERROR = "internal_error";

    private String result;
    private String accessToken;
    private String refreshToken;
    private long loginTime;
    private int accessTokenExpiresIn; // Access token expiration time in seconds
    
    /**
     * Constructor for error cases.
     *
     * @param result the result string
     */
    public RefreshTokenResponse(String result) {
        this.result = result;
    }
    
    /**
     * Constructor for success cases.
     *
     * @param accessToken the access token
     * @param refreshToken the refresh token
     * @param loginTime the login time
     * @param accessTokenExpiresIn the access token expiration time in seconds
     */
    public RefreshTokenResponse(String accessToken, String refreshToken, long loginTime, int accessTokenExpiresIn) {
        this.result = RESULT_SUCCESS;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.loginTime = loginTime;
        this.accessTokenExpiresIn = accessTokenExpiresIn;
    }
    
    /**
     * Check if the operation was successful.
     *
     * @return true if the operation was successful, false otherwise
     */
    public boolean isSuccess() {
        return RESULT_SUCCESS.equals(result);
    }
    
    /**
     * Get the result.
     *
     * @return the result
     */
    public String getResult() {
        return result;
    }
    
    /**
     * Set the result.
     *
     * @param result the result to set
     */
    public void setResult(String result) {
        this.result = result;
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