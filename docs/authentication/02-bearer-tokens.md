# Bearer Token Authentication

## Introduction

Bearer Token Authentication is an HTTP authentication scheme defined in **RFC 6750** as part of the OAuth 2.0 framework. The name "bearer" means that any party in possession of the token (the "bearer") can use it to access the protected resource -- no additional proof of identity is required.

Think of a bearer token like a concert ticket: whoever holds the ticket gets in, regardless of who originally purchased it. This simplicity makes bearer tokens extremely popular, but it also means that **token protection is critical** -- if a token is leaked, anyone can use it.

Bearer tokens are the dominant authentication mechanism for modern REST APIs, single-page applications (SPAs), and mobile applications.

---

## How It Works (Step-by-Step)

1. **Client authenticates** with the authorization server using valid credentials (username/password, client credentials, authorization code, etc.).
2. **Authorization server validates** the credentials and issues a bearer token.
3. **Client stores the token** securely (in memory, secure storage, or HTTP-only cookies).
4. **Client includes the token** in the `Authorization` header of each API request: `Authorization: Bearer <token>`.
5. **Resource server validates the token** -- either by checking a local store, calling the authorization server's introspection endpoint, or verifying a self-contained token (like a JWT).
6. **If valid**, the server processes the request and returns the response.
7. **If invalid or expired**, the server returns `401 Unauthorized`.

---

## Flow Diagram

```
 CLIENT                    AUTH SERVER                 RESOURCE SERVER
   |                           |                              |
   |  1. POST /oauth/token     |                              |
   |     grant_type=password   |                              |
   |     username=admin        |                              |
   |     password=s3cret       |                              |
   | ------------------------> |                              |
   |                           |                              |
   |     +---------------------+-----+                        |
   |     | AUTH SERVER:               |                        |
   |     | a. Validate credentials    |                        |
   |     | b. Generate token          |                        |
   |     | c. Store token metadata    |                        |
   |     |    (expiry, scopes, user)  |                        |
   |     +---------------------+-----+                        |
   |                           |                              |
   |  2. 200 OK               |                              |
   |     {                     |                              |
   |       "access_token":    |                              |
   |         "eyJhbGci...",    |                              |
   |       "token_type":       |                              |
   |         "Bearer",         |                              |
   |       "expires_in": 3600  |                              |
   |     }                     |                              |
   | <------------------------ |                              |
   |                           |                              |
   |  [Client stores token securely]                          |
   |                           |                              |
   |  3. GET /api/resource     |                              |
   |     Authorization: Bearer eyJhbGci...                    |
   | ---------------------------------------------------------|-->
   |                           |                              |
   |                           |   +------------------------+ |
   |                           |   | RESOURCE SERVER:        | |
   |                           |   | a. Extract token from   | |
   |                           |   |    Authorization header | |
   |                           |   | b. Validate token:      | |
   |                           |   |    - Check signature    | |
   |                           |   |    - Check expiration   | |
   |                           |   |    - Check scopes       | |
   |                           |   | c. Extract user context | |
   |                           |   +------------------------+ |
   |                           |                              |
   |  4. 200 OK               |                              |
   |     { "data": "..." }    |                              |
   | <---------------------------------------------------------|
   |                           |                              |


   Token Validation Strategies:

   Strategy A: Self-Contained Token (JWT)
   +--------------------------------------------------+
   |  Resource server validates locally:               |
   |  - Verify cryptographic signature                 |
   |  - Check expiration claim (exp)                   |
   |  - Check audience claim (aud)                     |
   |  - No network call needed                         |
   +--------------------------------------------------+

   Strategy B: Opaque Token + Introspection
   +--------------------------------------------------+
   |  RESOURCE SERVER            AUTH SERVER           |
   |       |                          |                |
   |       | POST /introspect         |                |
   |       |   token=abc123           |                |
   |       | -----------------------> |                |
   |       |                          |                |
   |       | { "active": true,        |                |
   |       |   "scope": "read write", |                |
   |       |   "sub": "user123" }     |                |
   |       | <----------------------- |                |
   +--------------------------------------------------+
```

---

## Token Types: Opaque vs. Self-Contained

```
  OPAQUE TOKEN                        SELF-CONTAINED TOKEN (JWT)
  +------------------+                +----------------------------------+
  | "a3f8b2c1d4e5"   |                | eyJhbGciOiJSUzI1NiJ9.           |
  |                   |                | eyJzdWIiOiJ1c2VyMTIzIi           |
  | - Random string   |                |  wiaWF0IjoxNjk5MDAwMDAwfQ.      |
  | - No embedded     |                | SflKxwRJSMeKKF2QT4fw...         |
  |   information     |                |                                  |
  | - Must query      |                | - Contains claims (payload)      |
  |   auth server     |                | - Cryptographically signed       |
  |   to validate     |                | - Verified locally               |
  | - Easy to revoke  |                | - Harder to revoke (until expiry)|
  +------------------+                +----------------------------------+
```

---

## Pros and Cons

| Pros | Cons |
|------|------|
| Decouples authentication from the resource server | Token leakage grants full access to the bearer |
| Supports fine-grained scopes and permissions | Revocation can be difficult (especially JWTs) |
| Stateless validation possible with JWTs | Token storage on the client must be handled carefully |
| Works across domains (no cookie restrictions) | Tokens transmitted in headers are visible in logs if not careful |
| Language and platform agnostic | Requires HTTPS -- tokens in plaintext over HTTP are catastrophic |
| Scales well in distributed systems | Token size can become large (especially JWTs with many claims) |
| Well-standardized (RFC 6750) | Clock skew issues with expiration validation |

---

## Real-World Use Cases

- **REST APIs** -- The vast majority of modern APIs use bearer tokens (GitHub, Stripe, Twilio, AWS).
- **Single-Page Applications (SPAs)** -- React/Angular/Vue apps authenticate via bearer tokens stored in memory.
- **Mobile applications** -- iOS and Android apps use bearer tokens after OAuth 2.0 flows.
- **Microservice architectures** -- Services pass bearer tokens to authenticate inter-service calls.
- **Third-party integrations** -- Platforms issue bearer tokens to allow external apps to access user data.
- **Serverless functions** -- Lambda/Cloud Functions validate incoming bearer tokens without session state.

---

## When to Use

- You are building a REST API consumed by web, mobile, or server clients.
- You need stateless authentication that scales horizontally.
- You want to implement OAuth 2.0 or OpenID Connect.
- Your architecture involves multiple services that need to trust the same token.
- You need scoped, time-limited access to resources.

## When NOT to Use

- For server-rendered web applications where HTTP-only session cookies are simpler and safer.
- When you cannot guarantee HTTPS on all communication channels.
- When token storage on the client is too risky (e.g., highly sensitive financial data in a browser extension).
- For simple internal tools where Basic Auth or mutual TLS is sufficient.

---

## Security Considerations

### 1. Token Storage

| Platform | Recommended Storage | Avoid |
|----------|-------------------|-------|
| Browser (SPA) | In-memory variable | localStorage, sessionStorage |
| Browser (traditional) | HTTP-only, Secure, SameSite cookie | JavaScript-accessible cookies |
| Mobile (iOS) | Keychain | UserDefaults, files |
| Mobile (Android) | EncryptedSharedPreferences | SharedPreferences, files |
| Server | Environment variables, secret managers | Source code, config files in repos |

### 2. Token Lifetime
Keep access tokens **short-lived** (5-60 minutes). Use refresh tokens for long-lived sessions. This limits the damage window if a token is compromised.

### 3. Token Revocation
- **Opaque tokens:** Maintain a server-side store; delete the entry to revoke.
- **JWTs:** Use short expiration times and maintain a revocation list (blocklist) for immediate revocation needs.

### 4. Scope Restriction
Always issue tokens with the **minimum required scopes**. A token for reading user profiles should not have write access to billing data.

### 5. Audience Restriction
Include an `aud` (audience) claim in self-contained tokens to ensure a token issued for Service A cannot be replayed against Service B.

### 6. Transport Security
- Always use HTTPS.
- Set `Strict-Transport-Security` headers.
- Never include tokens in URLs (query parameters are logged by servers, proxies, and browsers).

### 7. Token Binding
Consider binding tokens to a specific client using techniques like DPoP (Demonstration of Proof-of-Possession) defined in RFC 9449, which prevents stolen tokens from being used by different clients.

---

## Comparison: Bearer Token Transmission Methods

| Method | Security | Ease of Use | Notes |
|--------|----------|-------------|-------|
| `Authorization: Bearer <token>` | High | High | **Recommended.** Standard approach. |
| Query parameter `?access_token=<token>` | Low | High | **Avoid.** Tokens leak in server logs and browser history. |
| Form-encoded body `access_token=<token>` | Medium | Medium | Usable for POST requests only. Rarely used. |
| Cookie-based (token in cookie) | High* | Medium | Requires CSRF protection. Good for same-origin web apps. |

*When using HTTP-only, Secure, SameSite cookies.

---

## Code Example

### Server Middleware (Pseudocode)

```python
def bearer_auth_middleware(request):
    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Bearer "):
        return Response(
            status=401,
            headers={"WWW-Authenticate": 'Bearer realm="API"'},
            body={"error": "missing_token"}
        )

    token = auth_header.split(" ", 1)[1]

    try:
        # For JWT tokens: verify signature and claims
        payload = jwt.verify(token, public_key, algorithms=["RS256"])

        # Check required scopes
        if required_scope not in payload.get("scope", "").split():
            return Response(
                status=403,
                headers={
                    "WWW-Authenticate": 'Bearer error="insufficient_scope"'
                },
                body={"error": "insufficient_scope"}
            )

        request.user = payload["sub"]
        return handle_request(request)

    except jwt.ExpiredTokenError:
        return Response(
            status=401,
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            body={"error": "token_expired"}
        )
    except jwt.InvalidTokenError:
        return Response(
            status=401,
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            body={"error": "invalid_token"}
        )
```

---

## Summary

Bearer Token Authentication is the workhorse of modern API security. It provides a clean, stateless, and scalable mechanism for authenticating requests across distributed systems. The trade-off is that token management -- issuance, storage, validation, rotation, and revocation -- must be handled with care. When combined with HTTPS, short token lifetimes, and proper storage practices, bearer tokens offer an excellent balance of security and developer experience.

---

*Previous: [Basic Authentication](./01-basic-authentication.md) | Next: [API Key Authentication](./03-api-keys.md)*
