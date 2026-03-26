# Token-Based Authorization with JWTs

## Introduction

Token-based authorization is a pattern where the server issues a **self-contained token**
to a client after successful authentication, and the client presents this token with every
subsequent request. The server validates the token and extracts the authorization information
(roles, permissions, scopes) from it, without needing to query a database or session store.

The most popular token format is the **JSON Web Token (JWT)**, defined in RFC 7519. JWTs
are compact, URL-safe, and can carry arbitrary claims (key-value pairs) that describe the
user and their authorization context. They are cryptographically signed, so the server can
verify their authenticity without a central authority.

Token-based authorization has become the backbone of modern distributed systems, APIs, and
microservice architectures. It replaced server-side sessions as the dominant pattern because
tokens are **stateless** -- any server in a cluster can validate a token independently,
without sharing session state.

---

## JWT Structure

A JWT consists of three Base64URL-encoded parts separated by dots:

```
  eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNl...<signature>
  |___________________________________|.|______________________________________________|.|__________|
              HEADER                                     PAYLOAD                         SIGNATURE
```

### Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-2024-03"
}
```

- `alg` -- The signing algorithm (HS256, RS256, ES256, EdDSA).
- `typ` -- Token type (always "JWT").
- `kid` -- Key ID, used to select which public key to use for verification (important for key rotation).

### Payload (Claims)

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-12345",
  "aud": "https://api.example.com",
  "exp": 1711500000,
  "iat": 1711496400,
  "nbf": 1711496400,
  "jti": "unique-token-id-abc",
  "name": "Alice Johnson",
  "email": "alice@example.com",
  "roles": ["admin", "editor"],
  "permissions": ["read:articles", "write:articles", "manage:users"],
  "org_id": "org-789",
  "plan": "enterprise"
}
```

**Registered Claims (RFC 7519):**

| Claim | Name       | Description                                          |
|-------|------------|------------------------------------------------------|
| `iss` | Issuer     | Who issued the token (your auth server URL)          |
| `sub` | Subject    | Who the token represents (user ID)                   |
| `aud` | Audience   | Who the token is intended for (API URL or client ID) |
| `exp` | Expiration | When the token expires (Unix timestamp)              |
| `iat` | Issued At  | When the token was issued (Unix timestamp)           |
| `nbf` | Not Before | Token is not valid before this time                  |
| `jti` | JWT ID     | Unique identifier for this token (for revocation)    |

**Custom Claims:** Any additional data your application needs for authorization decisions.

### Signature

The signature is created by signing the encoded header and payload:

```
SIGNATURE = SIGN(
  BASE64URL(header) + "." + BASE64URL(payload),
  secret_or_private_key
)
```

---

## How It Works (Step by Step)

1. **Authentication** -- The user logs in with credentials (username/password, OAuth, SSO).
   The authentication server verifies the identity.

2. **Token Issuance** -- The auth server creates a JWT containing the user's identity and
   authorization claims (roles, permissions, scopes). The token is signed with a secret
   (HMAC) or private key (RSA/ECDSA).

3. **Token Delivery** -- The JWT is returned to the client, typically in a JSON response body
   (for SPAs/mobile) or as an HttpOnly cookie (for web apps using BFF pattern).

4. **Token Storage** -- The client stores the token securely (memory, HttpOnly cookie,
   secure storage on mobile).

5. **Request with Token** -- On every API request, the client includes the JWT in the
   `Authorization` header: `Authorization: Bearer eyJhbGci...`.

6. **Token Validation** -- The resource server validates the token:
   - Verify the signature using the public key or shared secret.
   - Check `exp` to ensure the token has not expired.
   - Check `iss` to ensure it was issued by a trusted authority.
   - Check `aud` to ensure the token is intended for this service.
   - Check `nbf` to ensure the token is active.

7. **Authorization Decision** -- The resource server reads the claims (roles, permissions)
   from the validated token and makes the authorization decision locally, with no database
   lookup required.

8. **Token Refresh** -- When the access token expires, the client uses a refresh token
   (opaque, stored server-side) to obtain a new JWT.

---

## Token-Based Authorization Flow (ASCII Diagram)

```
   +----------+                  +-------------------+               +------------------+
   |  Client  |                  |  Auth Server      |               | Resource Server  |
   | (Browser/|                  | (issues tokens)   |               | (API)            |
   |  Mobile) |                  +-------------------+               +------------------+
   +----+-----+                          |                                   |
        |                                |                                   |
        | (1) POST /auth/login           |                                   |
        |   { email, password }          |                                   |
        +------------------------------->|                                   |
        |                                |                                   |
        |                   (2) Verify credentials                           |
        |                       Look up user roles/perms                     |
        |                       Build JWT payload                            |
        |                       Sign with private key                        |
        |                                |                                   |
        | (3) Response:                  |                                   |
        |   { access_token: "eyJ...",    |                                   |
        |     refresh_token: "abc...",   |                                   |
        |     expires_in: 900 }          |                                   |
        |<-------------------------------+                                   |
        |                                                                    |
        |  (4) Store token securely                                          |
        |      (memory / HttpOnly cookie)                                    |
        |                                                                    |
        |  (5) GET /api/articles                                             |
        |      Authorization: Bearer eyJ...                                  |
        +------------------------------------------------------------------->|
        |                                                                    |
        |                                                    (6) Validate JWT:
        |                                                    - Verify signature
        |                                                    - Check exp, iss, aud
        |                                                    - Extract claims:
        |                                                      roles: [editor]
        |                                                      perms: [read:articles,
        |                                                              write:articles]
        |                                                                    |
        |                                                    (7) Check permission:
        |                                                    "read:articles" in perms?
        |                                                    YES -> proceed
        |                                                                    |
        |  (8) 200 OK                                                        |
        |      [{ article data }]                                            |
        |<-------------------------------------------------------------------+
        |                                                                    |
        |                                                                    |

  TOKEN REFRESH FLOW:

        |  (Access token expired)                                            |
        |                                                                    |
        |  GET /api/articles  -> 401 Unauthorized                            |
        |<-------------------------------------------------------------------+
        |                                                                    |
        |  POST /auth/refresh                                                |
        |    { refresh_token: "abc..." }                                     |
        +------------------------------->|                                   |
        |                                |                                   |
        |                   Validate refresh token (DB lookup)               |
        |                   Issue new JWT                                     |
        |                   (Optionally rotate refresh token)                |
        |                                |                                   |
        |  { access_token: "eyJ..new..", |                                   |
        |    refresh_token: "def..." }   |                                   |
        |<-------------------------------+                                   |
        |                                                                    |
        |  Retry original request with new token                             |
        +------------------------------------------------------------------->|
```

---

## Signing Algorithms

### Symmetric (HMAC)

Both the issuer and verifier share the same secret key.

```
  Auth Server                              Resource Server
  +------------------+                     +------------------+
  | SECRET_KEY: xyz  |                     | SECRET_KEY: xyz  |
  | Sign JWT with    |                     | Verify JWT with  |
  | HMAC-SHA256(xyz) |                     | HMAC-SHA256(xyz) |
  +------------------+                     +------------------+

  Algorithms: HS256, HS384, HS512
  Use when: Auth server and resource server are the same service (monolith)
  Risk: Anyone with the secret can both create AND verify tokens
```

### Asymmetric (RSA / ECDSA / EdDSA)

The issuer signs with a private key; verifiers use the public key.

```
  Auth Server                              Resource Server(s)
  +------------------+                     +------------------+
  | PRIVATE KEY      |                     | PUBLIC KEY       |
  | (kept secret)    |                     | (freely shared)  |
  |                  |                     |                  |
  | Sign JWT with    |     JWKS endpoint   | Verify JWT with  |
  | RSA-SHA256       |  /.well-known/jwks  | RSA-SHA256       |
  +------------------+  ----------------->  +------------------+
                                            +------------------+
                                            | Another Service  |
                                            | PUBLIC KEY       |
                                            | Verify JWT       |
                                            +------------------+

  Algorithms: RS256, RS384, RS512 (RSA)
              ES256, ES384, ES512 (ECDSA -- smaller, faster)
              EdDSA (Ed25519 -- modern, fast)

  Use when: Multiple services need to verify tokens (microservices)
  Advantage: Resource servers cannot forge tokens
```

### JWKS (JSON Web Key Set)

Resource servers fetch public keys from the auth server's JWKS endpoint:

```
GET https://auth.example.com/.well-known/jwks.json

{
  "keys": [
    {
      "kty": "RSA",
      "kid": "key-2024-03",
      "use": "sig",
      "n": "0vx7agoebGcQ...",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "kid": "key-2024-06",
      "use": "sig",
      "n": "pjdss8ZaDf...",
      "e": "AQAB"
    }
  ]
}
```

The `kid` in the JWT header tells the verifier which key to use, enabling seamless **key rotation**.

---

## Authorization Patterns with JWTs

### Pattern 1: Role-Based (RBAC in JWT)

```json
{
  "sub": "user-123",
  "roles": ["editor", "reviewer"]
}
```

```python
# Middleware
def require_role(role):
    def decorator(handler):
        def wrapper(request):
            token = validate_jwt(request.headers["Authorization"])
            if role not in token["roles"]:
                raise ForbiddenError()
            return handler(request)
        return wrapper
    return decorator

@require_role("editor")
def create_article(request):
    ...
```

### Pattern 2: Permission-Based (Fine-Grained)

```json
{
  "sub": "user-123",
  "permissions": ["articles:read", "articles:write", "users:read"]
}
```

```python
@require_permission("articles:write")
def create_article(request):
    ...
```

### Pattern 3: Scope-Based (OAuth2 Tokens)

```json
{
  "sub": "user-123",
  "scope": "read:articles write:articles",
  "client_id": "app-456"
}
```

### Pattern 4: Multi-Tenant

```json
{
  "sub": "user-123",
  "org_id": "org-789",
  "org_role": "admin",
  "tenant_permissions": {
    "org-789": ["admin"],
    "org-101": ["viewer"]
  }
}
```

---

## Real-World Examples

### Auth0 / Okta

Auth0 issues JWTs as access tokens with custom claims. Their "Actions" feature lets you
enrich tokens with roles and permissions at issuance time:

```json
{
  "iss": "https://your-tenant.auth0.com/",
  "sub": "auth0|abc123",
  "aud": "https://api.example.com",
  "azp": "client-id-xyz",
  "scope": "openid profile email",
  "permissions": ["read:items", "create:items"],
  "https://example.com/roles": ["admin"]
}
```

### Firebase Authentication

Firebase issues JWTs with custom claims that can be used in Firestore Security Rules:

```javascript
// Set custom claims (server-side)
admin.auth().setCustomUserClaims(uid, {
  admin: true,
  accessLevel: 5
});

// JWT payload will include:
// { ..., admin: true, accessLevel: 5, ... }

// Firestore rules use these claims:
// allow write: if request.auth.token.admin == true;
```

### Stripe API

Stripe uses bearer tokens (API keys that function as opaque tokens) for API authorization.
While not JWTs internally, the pattern is the same: include the token in every request,
and the server determines access based on the token's associated permissions.

### Kubernetes Service Accounts

Kubernetes issues JWTs to pods via service account tokens. These tokens are projected into
the pod's filesystem and used to authenticate with the Kubernetes API server, which then
applies RBAC policies.

```json
{
  "iss": "https://kubernetes.default.svc",
  "sub": "system:serviceaccount:default:my-app",
  "aud": ["https://kubernetes.default.svc"],
  "exp": 1711500000,
  "kubernetes.io": {
    "namespace": "default",
    "serviceaccount": { "name": "my-app", "uid": "..." }
  }
}
```

---

## Token Revocation: The Hard Problem

The biggest challenge with JWTs is that they are **self-contained and stateless**. Once
issued, a JWT is valid until it expires. If a user is deactivated or their permissions
change, the old JWT still works until `exp`.

### Revocation Strategies

```
  Strategy 1: Short Expiry + Refresh Tokens
  ==========================================

  Access Token TTL: 5-15 minutes
  Refresh Token: Stored in DB, revocable

  +------ Access Token Valid ------+-- Expired --+
  |         (5-15 min)             |             |
  | Server trusts token blindly.   | Client must |
  | No DB check needed.            | refresh.    |
  +--------------------------------+ Server can  |
                                     deny refresh|
                                     if revoked. |
                                   +-------------+

  Worst case: 5-15 minute window where revoked user still has access.


  Strategy 2: Token Blocklist (Denylist)
  =======================================

  On revocation, add the token's `jti` to a fast store (Redis).
  On every request, check the blocklist.

  +-------------------+       +-----------------------+
  | Resource Server   |       | Redis Blocklist       |
  |                   | ----> | jti: "abc" -> revoked |
  | Validate JWT:     |       | jti: "def" -> revoked |
  | 1. Verify sig     |       | TTL = token's remaining|
  | 2. Check exp      |       | lifetime              |
  | 3. Check blocklist|       +-----------------------+
  +-------------------+

  Tradeoff: Adds a network call to every request (partially defeats statelessness).


  Strategy 3: Token Versioning
  ============================

  Store a "token_version" per user in the DB (or cache).
  Include the version in the JWT. On validation, compare.

  JWT: { sub: "user-123", token_version: 7 }
  DB:  user-123 -> current_token_version: 8  (was bumped on revocation)
  Result: 7 != 8 -> DENY

  Tradeoff: Requires a DB/cache lookup per request (per user, not per token).


  Strategy 4: Short-Lived Tokens Only (No Refresh)
  =================================================

  Issue tokens with 1-5 minute expiry. Client re-authenticates frequently.
  Suitable for internal microservice-to-microservice tokens.
```

---

## Pros and Cons

### Advantages

- **Stateless** -- No server-side session storage needed. Any server can validate independently.
- **Scalable** -- Perfect for distributed systems, microservices, and serverless.
- **Self-Contained** -- The token carries all authorization information. No database lookup
  on every request.
- **Cross-Domain** -- JWTs work seamlessly across different services and domains.
- **Standard** -- RFC 7519 is universally supported. Libraries exist for every language.
- **Debuggable** -- Paste a JWT into jwt.io to inspect its claims (the payload is only
  Base64-encoded, not encrypted).

### Disadvantages

- **Not Immediately Revocable** -- Revoking a JWT requires extra infrastructure (blocklists,
  short expiry + refresh).
- **Size** -- JWTs are larger than opaque tokens or session IDs. With many claims, they can
  exceed cookie size limits (4KB) or add significant overhead to every request.
- **Sensitive Data Exposure** -- JWT payloads are Base64-encoded, not encrypted. Never put
  secrets in a JWT unless you use JWE (JSON Web Encryption).
- **Complexity** -- Correct JWT implementation requires understanding signing algorithms,
  key rotation, claim validation, and token lifecycle management.
- **Stale Claims** -- If a user's roles change, the JWT still contains the old roles until
  it expires and is refreshed.
- **Algorithm Confusion Attacks** -- Historic vulnerability where attackers change `alg` to
  `none` or switch from RS256 to HS256 using the public key as the HMAC secret. Modern
  libraries mitigate this, but you must configure allowed algorithms explicitly.

---

## When to Use Token-Based Authorization

**Use JWTs when:**

- You have a distributed system (microservices, serverless) where session sharing is impractical.
- You need cross-service authorization (service A issues a token that service B validates).
- You want to embed authorization claims (roles, permissions) directly in the token.
- You are building a public API consumed by third-party clients.
- You need to scale horizontally without shared state.
- You are using OAuth2 or OpenID Connect (JWTs are the standard token format).

**Avoid JWTs when:**

- You need instant revocation (use server-side sessions or opaque tokens with introspection).
- Your tokens would be very large (too many claims, nested objects).
- You are building a simple monolithic web app (server-side sessions are simpler and offer
  immediate revocation).
- You are tempted to store sensitive data in the token (use JWE or keep data server-side).
- You do not have the expertise to implement JWT validation correctly (algorithm verification,
  claim checking, key rotation).

---

## Implementation Considerations

### Security Checklist

```
  [ ] Use asymmetric signing (RS256 or ES256) for distributed systems
  [ ] Explicitly configure allowed algorithms (NEVER accept "none")
  [ ] Validate ALL registered claims: iss, sub, aud, exp, nbf
  [ ] Set short expiry (5-15 min for access tokens)
  [ ] Use refresh tokens for session continuity (stored server-side)
  [ ] Implement key rotation via JWKS with kid
  [ ] Never store sensitive data in JWT payload (it is NOT encrypted)
  [ ] Store tokens securely (HttpOnly cookies for web, Keychain for mobile)
  [ ] Implement token revocation strategy (blocklist or token versioning)
  [ ] Set appropriate audience (aud) to prevent token misuse across services
  [ ] Use HTTPS everywhere (tokens in transit must be encrypted)
  [ ] Limit token size (avoid embedding large objects)
```

### Key Rotation Strategy

```
  Phase 1: Generate new key pair (kid: "key-v2")
  Phase 2: Sign new tokens with key-v2, publish both keys in JWKS
  Phase 3: Wait for all key-v1 tokens to expire
  Phase 4: Remove key-v1 from JWKS

  JWKS at Phase 2:
  {
    "keys": [
      { "kid": "key-v1", ... },   <-- still used for verification
      { "kid": "key-v2", ... }    <-- used for signing + verification
    ]
  }

  Timeline:
  |------- key-v1 active -------|
                     |------- key-v2 active ------->
                     |-- overlap --|
                     (both keys in JWKS)
```

### Token Size Optimization

Keep JWTs lean. Embed only what is needed for authorization decisions:

```
  BAD (bloated token, 2KB+):
  {
    "sub": "user-123",
    "name": "Alice Johnson",
    "email": "alice@example.com",
    "avatar": "https://cdn.example.com/avatars/alice.jpg",
    "address": { "street": "123 Main St", ... },
    "preferences": { "theme": "dark", "language": "en", ... },
    "permissions": ["perm1", "perm2", ... "perm50"],
    "groups": ["group1", "group2", ... "group20"]
  }

  GOOD (minimal token, ~500 bytes):
  {
    "sub": "user-123",
    "roles": ["admin"],
    "org_id": "org-789",
    "scope": "read write"
  }

  Fetch profile data and detailed permissions from the API when needed,
  not from the token.
```

---

## Comparison with Other Approaches

| Dimension              | JWT (Self-Contained)  | Opaque Token + Introspection | Server-Side Session |
|------------------------|-----------------------|------------------------------|---------------------|
| State                  | Stateless             | Stateful (token store)       | Stateful (session store) |
| Validation             | Local (no network)    | Network call to auth server  | Session store lookup |
| Revocation             | Hard (needs blocklist) | Immediate (delete from store)| Immediate (delete session) |
| Scalability            | Excellent             | Limited by token store       | Limited by session store |
| Cross-service          | Easy                  | Requires shared token store  | Requires shared session store |
| Token size             | Large (claims inside) | Small (just an ID)           | Small (just session ID) |
| Information leakage    | Possible (Base64)     | None (opaque)                | None (server-side) |
| Offline validation     | Yes                   | No                           | No |

---

## Anti-Patterns to Avoid

1. **Storing JWTs in localStorage** -- Vulnerable to XSS. Use HttpOnly cookies or in-memory storage.

2. **Using JWTs as session replacements** -- If you need server-side session features
   (immediate revocation, session listing), use actual sessions.

3. **Long-lived JWTs without refresh** -- A JWT with a 30-day expiry is essentially an
   unrevocable API key. Use short-lived access tokens + refresh tokens.

4. **Accepting `alg: none`** -- Always validate the algorithm. Configure your library to
   accept only specific algorithms.

5. **Not validating `aud`** -- A token meant for Service A should not be accepted by Service B.
   Always check the audience claim.

6. **Putting secrets in the payload** -- The payload is Base64-encoded, not encrypted. Anyone
   can decode it. Use JWE if you need encrypted tokens.

7. **Not rotating keys** -- If your signing key is compromised and you have never rotated,
   all tokens ever issued are compromised. Rotate regularly.

---

## Key Takeaways

1. JWTs are **self-contained tokens** that carry authorization information (claims) and are
   cryptographically signed to prevent tampering.
2. They enable **stateless authorization** -- any server can validate a token independently.
3. The three parts (Header, Payload, Signature) work together to provide integrity and
   authenticity.
4. Use **asymmetric signing** (RS256/ES256) for distributed systems so that resource servers
   cannot forge tokens.
5. The hardest problem is **revocation** -- short-lived tokens + refresh tokens is the most
   common solution.
6. JWTs are not a silver bullet. For simple web apps, server-side sessions may be simpler
   and more secure. For distributed systems and APIs, JWTs are the industry standard.

---

## Further Reading

- RFC 7519: JSON Web Token (JWT)
- RFC 7515: JSON Web Signature (JWS)
- RFC 7516: JSON Web Encryption (JWE)
- RFC 7517: JSON Web Key (JWK)
- RFC 7518: JSON Web Algorithms (JWA)
- jwt.io: Interactive JWT debugger and library directory
- Auth0 Blog: "Critical vulnerabilities in JSON Web Token libraries"
- OWASP: JSON Web Token Cheat Sheet
