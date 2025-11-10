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

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Configuration properties for resource server security.
 * These properties can be configured in application.yml or application.properties.
 */
@ConfigurationProperties(prefix = "jauth.security")
@Component
public class ResourceSecurityProperties {

    /**
     * 客户端类型请求头名称
     */
    private String clientTypeHeaderName;

    private Map<String, String> publicKeys;

    /**
     * List of secure paths that require authentication.
     */
    private List<String> securePaths = List.of("/api/**");

    /**
     * List of paths that are permitted without authentication.
     */
    private List<String> permitAllPaths = List.of("/actuator/health");

    /**
     * Get the list of secure paths.
     *
     * @return the list of secure paths
     */
    public List<String> getSecurePaths() {
        return securePaths;
    }

    /**
     * Set the list of secure paths.
     *
     * @param securePaths the list of secure paths to set
     */
    public void setSecurePaths(List<String> securePaths) {
        this.securePaths = securePaths;
    }

    /**
     * Get the list of permit-all paths.
     *
     * @return the list of permit-all paths
     */
    public List<String> getPermitAllPaths() {
        return permitAllPaths;
    }

    /**
     * Set the list of permit-all paths.
     *
     * @param permitAllPaths the list of permit-all paths to set
     */
    public void setPermitAllPaths(List<String> permitAllPaths) {
        this.permitAllPaths = permitAllPaths;
    }

    public Map<String, String> getPublicKeys() {
        return publicKeys;
    }

    public String getClientTypeHeaderName() {
        return clientTypeHeaderName;
    }
}