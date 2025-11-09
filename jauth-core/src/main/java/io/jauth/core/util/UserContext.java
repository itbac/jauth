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

package io.jauth.core.util;

/**
 * Utility class for managing user context.
 * This class provides thread-local storage for user ID.
 */
public class UserContext {
    
    private static final ThreadLocal<String> userContext = new ThreadLocal<>();
    
    /**
     * Set the user ID in the context.
     *
     * @param userId the user ID to set
     */
    public static void setUserId(String userId) {
        userContext.set(userId);
    }
    
    /**
     * Get the user ID from the context.
     *
     * @return the user ID, or null if not set
     */
    public static String getUserId() {
        return userContext.get();
    }
    
    /**
     * Clear the user context.
     */
    public static void clear() {
        userContext.remove();
    }
}