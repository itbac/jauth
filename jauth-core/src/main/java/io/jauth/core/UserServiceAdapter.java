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

package io.jauth.core;

/**
 * User service adapter interface for retrieving user information.
 * Implementations of this interface should provide methods for validating
 * user credentials and retrieving user details for token generation.
 */
public interface UserServiceAdapter {

    /**
     * Authenticate a user with the given username and password.
     *
     * @param username the username
     * @param password the password
     * @return true if the credentials are valid, false otherwise
     */
    boolean authenticate(String username, String password);

    /**
     * Get user ID by username.
     *
     * @param username the username
     * @return the user ID, or null if not found
     */
    String getUserIdByUsername(String username);

    /**
     * Check if a user is valid.
     *
     * @param userId the user ID
     * @return true if the user is valid, false otherwise
     */
    boolean isUserValid(String userId);
}