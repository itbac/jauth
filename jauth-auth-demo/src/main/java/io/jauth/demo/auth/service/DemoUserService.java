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

package io.jauth.demo.auth.service;

import io.jauth.demo.auth.api.UserService;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * Demo implementation of UserServiceAdapter.
 * This service provides user validation and user details for the authentication process.
 */
@Service
public class DemoUserService implements UserService {
    
    // In-memory user storage for demo purposes
    private static final Map<String, User> USERS = new HashMap<>();
    private static final Map<String, String> USER_ID_TO_USERNAME = new HashMap<>();
    
    static {
        User user1 = new User("user1", "User One", "password1", "user1@example.com");
        User user2 = new User("user2", "User Two", "password2", "user2@example.com");
        USERS.put("user1", user1);
        USERS.put("user2", user2);
        USER_ID_TO_USERNAME.put("user1", "user1");
        USER_ID_TO_USERNAME.put("user2", "user2");
    }
    
    /**
     * Authenticate a user with the given username and password.
     *
     * @param username the username
     * @param password the password
     * @return true if the credentials are valid, false otherwise
     */
    @Override
    public String authenticate(String username, String password) {
        User user = USERS.get(username);
        if( user != null && user.getPassword().equals(password)){
            return user.getId();
        };
        return null;
    }
    
    /**
     * Get user ID by username.
     *
     * @param username the username
     * @return the user ID, or null if not found
     */
    @Override
    public String getUserIdByUsername(String username) {
        User user = USERS.get(username);
        return user != null ? user.getId() : null;
    }
    
    /**
     * Simple user class for demo purposes.
     */
    public static class User {
        private final String id;
        private final String username;
        private final String password;
        private final String email;
        private final String name;
        
        public User(String id, String name, String password, String email) {
            this.id = id;
            this.username = id;
            this.name = name;
            this.password = password;
            this.email = email;
        }
        
        public String getId() {
            return id;
        }
        
        public String getUsername() {
            return username;
        }
        
        public String getPassword() {
            return password;
        }
        
        public String getEmail() {
            return email;
        }
        
        public String getName() {
            return name;
        }
    }
}