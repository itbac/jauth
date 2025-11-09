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

package io.jauth.demo.resource.controller;

import io.jauth.core.util.UserContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller for protected resources.
 * This controller demonstrates how to access user information from the JWT token
 * in protected endpoints.
 */
@RestController
@RequestMapping("/api")
public class ProtectedController {

    /**
     * Protected endpoint that returns user information from the JWT token.
     *
     * @return a response entity with user information
     */
    @GetMapping("/user")
    public ResponseEntity<?> getUserInfo() {
        String currentUserId = UserContext.getUserId();
        if (currentUserId == null) {
            return ResponseEntity.status(401).body("User not authenticated");
        }

        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("userId", currentUserId);
        userInfo.put("message", "Hello, authenticated user!");

        return ResponseEntity.ok(userInfo);
    }

    /**
     * Public endpoint that doesn't require authentication.
     *
     * @return a response entity with a welcome message
     */
    @GetMapping("/public/welcome")
    public ResponseEntity<?> welcome() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Welcome to the JAuth resource demo application!");
        return ResponseEntity.ok(response);
    }
}