# JAuth

JAuth is a lightweight authentication and authorization framework for Java applications. It provides a simple and secure way to handle JWT-based authentication without relying on Spring Security.

## Features

- JWT-based authentication
- Refresh token support with Redis storage
- Web and mobile client support
- Easy integration with Spring Boot applications
- Secure signature validation for refresh tokens
- Configurable security headers

## Modules

### Core Package Structure

The core module is organized into the following packages:
- `io.jauth.core.api`: Contains all core interfaces
- `io.jauth.core.dto`: Contains data transfer objects
- `io.jauth.core.util`: Contains utility classes

### Module Structure

- **jauth-core**: Core utilities and interfaces
  - `JwtUtil`: JWT utility class for token generation and validation
  - `TokenGenerator`: Interface for token generation
  - `UserServiceAdapter`: Interface for user service integration
  - `UserContext`: Thread-local user context management
  - `AuthUtils`: Interface for authentication operations
  - `RefreshTokenService`: Interface for refresh token management

- **jauth-auth-starter**: Authentication starter with default implementations
  - `DefaultTokenGenerator`: Default implementation of TokenGenerator
  - `DefaultAuthUtils`: Default implementation of AuthUtils
  - `DefaultRefreshTokenService`: Default implementation of RefreshTokenService
  - `AuthAutoConfiguration`: Auto-configuration for authentication components

- **jauth-resource-starter**: Resource server starter with JWT filter
  - `JwtAuthenticationFilter`: JWT authentication filter
  - `ResourceSecurityProperties`: Configuration properties for resource security
  - `ResourceAutoConfiguration`: Auto-configuration for resource server components

- **jauth-auth-demo**: Demo application for authentication server
  - Example implementation of user service adapter
  - Sample authentication controller
  - Configuration properties

- **jauth-resource-demo**: Demo application for resource server
  - Example protected controller
  - Configuration properties

## Security Features

### JWT Secret Requirements
The JWT secret must be at least 32 characters long and should be 32, 64, or 128 characters for optimal security.

### Refresh Token Security
Refresh tokens are stored in Redis with additional security information:
- User ID (encrypted)
- Login time
- Signature generated from configurable security headers

When refreshing a token, the system validates:
- Token existence in Redis
- Login time matching (if provided)
- Signature validation using SHA-256 hash of security headers

### Signature Headers
The system uses configurable security headers to generate signatures for refresh tokens. By default, it uses common headers like User-Agent and X-Forwarded-For, but this can be customized through configuration.

### Cookie Security
For web clients, refresh tokens are stored in secure, HttpOnly cookies with configurable SameSite attributes.

## Configuration

### Authentication Server Configuration
```yaml
jauth:
  # Client type specific configurations
  # This allows different client types (web, app, mini-program) to use different secrets and token strategies
  client-type:
    web:
      secret: "your-web-client-secret-key-here-with-at-least-32-characters"
      access-token:
        expires-in: 3600  # 1 hour
      refresh-token:
        expires-in: 604800  # 7 days
        security:
          hash-algorithm: HMAC-SHA256
          signature-headers:
            - User-Agent
            - X-Forwarded-For
            - X-login-time
          cookie:
            same-site: Lax
            secure: true
    app:
      secret: "your-app-client-secret-key-here-with-at-least-32-characters"
      access-token:
        expires-in: 7200  # 2 hours
      refresh-token:
        expires-in: 1209600  # 14 days
        security:
          hash-algorithm: HMAC-SHA512
          signature-headers:
            - User-Agent
            - X-Forwarded-For
            - X-login-time
          cookie:
            same-site: None
            secure: true
    mini-program:
      secret: "your-mini-program-secret-key-here-with-at-least-32-characters"
      access-token:
        expires-in: 1800  # 30 minutes
      refresh-token:
        expires-in: 86400  # 1 day
        security:
          hash-algorithm: HMAC-SHA256
          signature-headers:
            - User-Agent
            - X-login-time
          cookie:
            same-site: Lax
            secure: true
  
  access-token:
    # Access token expiration time in seconds
    expires-in: 3600  # 1 hour
    # Signature algorithm for JWT tokens
    # Supported values: HMAC-SHA256, HMAC-SHA384, HMAC-SHA512, RS256, RS384, RS512
    algorithm: RS256
    # Public key for verifying JWT tokens (Base64 encoded)
    # public-key: "your-base64-encoded-public-key-here"
    # Private key for signing JWT tokens (Base64 encoded)
    # private-key: "your-base64-encoded-private-key-here"
  refresh-token:
    # Refresh token expiration time in seconds
    expires-in: 604800  # 7 days
    security:
      # Hash algorithm for signature generation (MD5, SHA-1, SHA-256, SHA-384, SHA-512, HMAC-SHA256, HMAC-SHA512)
      hash-algorithm: HMAC-SHA256
      # Headers used for generating refresh token signatures
      # When signature-headers-for-validation is not set, these headers will be used for both
      # signature generation and validation
      signature-headers:
        - User-Agent
        - X-Forwarded-For
        - X-login-time
        - Accept-Language
        - Accept-Encoding
      # Headers used specifically for signature validation
      # If not set, signature-headers will be used instead
      # This allows using a subset of headers for validation to reduce computation overhead
      # signature-headers-for-validation:
      #   - User-Agent
      #   - X-Forwarded-For
      #   - X-login-time
      cookie:
        same-site: Lax
        secure: true
  auth:
    ignored-paths:
      - /public/**
      - /actuator/**
```

### Resource Server Configuration
```yaml
jauth:
  resource:
    jwt-secret: "your-super-long-secret-key-here-with-at-least-32-characters"
    ignored-paths:
      - /public/**
      - /actuator/**
```

## Usage

### Adding Dependency
Add the following dependency to your pom.xml:

```xml
<dependency>
    <groupId>io.github.itbac</groupId>
    <artifactId>jauth-auth-starter</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

For resource servers:

```xml
<dependency>
    <groupId>io.github.itbac</groupId>
    <artifactId>jauth-resource-starter</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

### Implementing User Service
Implement the `UserServiceAdapter` interface to integrate with your user management system:

```java
@Service
public class CustomUserServiceAdapter implements UserServiceAdapter {
    @Override
    public boolean authenticate(String username, String password) {
        // Your authentication logic here
        return true;
    }

    @Override
    public String getUserIdByUsername(String username) {
        // Return user ID based on username
        return "user-id";
    }
}
```

### Using AuthUtils
The `AuthUtils` class provides convenient methods for authentication operations:

```java
@RestController
public class AuthController {
    
    @Autowired
    private AuthUtils authUtils;
    
    @PostMapping("/login")
    public LoginResponse login(@RequestParam String username, @RequestParam String password) {
        // Authenticate user
        if (userService.authenticate(username, password)) {
            String userId = userService.getUserIdByUsername(username);
            return authUtils.login(userId);
        }
        throw new AuthenticationException("Invalid credentials");
    }
}
```

## Recent Changes

### Package Restructuring
The core module has been restructured to improve organization:
- Interfaces are now in `io.jauth.core.api`
- DTOs are in `io.jauth.core.dto`
- Utilities are in `io.jauth.core.util`

### Refresh Token Service Improvements
- `RefreshTokenService` is now an interface in the core module
- `DefaultRefreshTokenService` provides the default implementation in the auth starter module
- Removed unused `redisLongTemplate` dependency for cleaner code
- Added conditional bean creation in `AuthAutoConfiguration` to ensure `RedisTemplate` is available

### Security Enhancements
- Improved signature validation for refresh tokens
- Better cookie management for web and mobile clients
- Enhanced error handling and response formats

## License
Apache License 2.0