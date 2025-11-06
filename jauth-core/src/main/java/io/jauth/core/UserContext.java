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
 * User context holder for storing and retrieving user information
 * in a thread-local context.
 */
public class UserContext {

    private static final ThreadLocal<String> CURRENT_USER_ID = new ThreadLocal<>();

    /**
     * Set the current user ID.
     *
     * @param userId the user ID to store in the context
     */
    public static void setCurrentUserId(String userId) {
        CURRENT_USER_ID.set(userId);
    }

    /**
     * Get the current user ID.
     *
     * @return the current user ID, or null if not set
     */
    public static String getCurrentUserId() {
        return CURRENT_USER_ID.get();
    }

    /**
     * Clear the current user ID.
     */
    public static void clear() {
        CURRENT_USER_ID.remove();
    }
}
