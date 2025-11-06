# JAuth - Lightweight authentication framework for Java
一个轻量级的Java认证框架。
JAuth is a lightweight authentication and authorization framework for Java applications. It provides a simple, secure, and easy-to-integrate authentication solution based on JWT and refresh tokens, without depending on Spring Security.

## Features

- JWT + Refresh Token authentication
- Multi-client support (Web and Mobile)
- ThreadLocal user context management
- Configurable secure and permit-all paths
- Standard JSON error responses
- Production-grade security implementation
- No Spring Security dependency

## Modules

- `jauth-core`: Core module with JWT utilities, token generators, and user context
- `jauth-auth-starter`: Auth starter with login, refresh, and logout endpoints
- `jauth-resource-starter`: Resource server starter with JWT authentication filter
- `jauth-auth-demo`: Demo application for authentication center
- `jauth-resource-demo`: Demo application for resource server

## Maven Dependencies

```xml
<!-- Resource Server Starter -->
<dependency>
    <groupId>io.github.itbac</groupId>
    <artifactId>jauth-resource-starter</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>

<!-- Auth Center Starter -->
<dependency>
    <groupId>io.github.itbac</groupId>
    <artifactId>jauth-auth-starter</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

## Quick Start

### Auth Center Setup

1. Add jauth-auth-starter dependency
2. Implement UserServiceAdapter interface
3. Configure Redis connection in application.yml:

```yaml
spring:
  redis:
    host: localhost
    port: 6379
```

### Resource Server Setup

1. Add jauth-resource-starter dependency
2. Configure secure paths in application.yml:

```yaml
jauth:
  security:
    secure-paths: 
      - "/api/**"
    permit-all-paths:
      - "/actuator/health"
      - "/public/**"
```

## Demo Applications

JAuth includes two demo applications to showcase how to use the framework:

### Auth Demo (jauth-auth-demo)

This demo shows how to set up an authentication center using JAuth. It includes:
- Implementation of UserServiceAdapter for user authentication
- Implementation of TokenGenerator for token creation
- In-memory user storage for demonstration purposes

To run the auth demo:
```bash
cd jauth-auth-demo
mvn spring-boot:run
```

The auth demo will start on port 8080.

### Resource Demo (jauth-resource-demo)

This demo shows how to set up a resource server using JAuth. It includes:
- Protected endpoints that require JWT authentication
- Public endpoints that don't require authentication

To run the resource demo:
```bash
cd jauth-resource-demo
mvn spring-boot:run
```

The resource demo will start on port 8081.

## API Endpoints

### Auth Endpoints (/api/auth)

#### POST /api/auth/login
Login with username and password
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600
}
```

#### POST /api/auth/refresh
Refresh access token
```bash
# For Web (using cookie)
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Cookie: refresh_token=your-refresh-token"

# For Mobile (using body)
curl -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"your-refresh-token","login_time":1234567890}'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600
}
```

#### POST /api/auth/logout
Logout and invalidate refresh token
```bash
curl -X POST http://localhost:8080/api/auth/logout \
  -H "Cookie: refresh_token=your-refresh-token"
```

### Protected Resource Access

Protected endpoints require a valid JWT access token in the Authorization header:
```bash
curl -X GET http://localhost:8081/api/user \
  -H "Authorization: Bearer your-access-token"
```

## License

Apache License 2.0