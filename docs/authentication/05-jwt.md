# JSON Web Tokens (JWT)

## Introduction

JSON Web Tokens (JWT, pronounced "jot") are a compact, URL-safe means of representing claims between two parties, defined in **RFC 7519**. A JWT is a self-contained token that carries all the information needed to authenticate a request and authorize access -- without requiring the server to look up session data in a database.

JWTs have become the de facto standard for stateless authentication in modern web applications, microservice architectures, and API ecosystems. They are used as access tokens in OAuth 2.0 flows, as identity tokens in OpenID Connect, and as a general-purpose mechanism for securely transmitting information between parties.

The power of JWTs lies in their cryptographic integrity: the token is digitally signed, so the recipient can verify that the claims have not been tampered with.

---

## JWT Structure

A JWT consists of three parts separated by dots (`.`):

```
  eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
  |___________________________________|.|___________________________________________________|.|_______________________________________|
               HEADER                                       PAYLOAD                                      SIGNATURE


  +------------------+     +---------------------------+     +----------------------+
  |     HEADER       |     |        PAYLOAD            |     |     SIGNATURE        |
  |                  |     |                           |     |                      |
  |  {               |     |  {                        |     |  HMACSHA256(         |
  |    "alg": "RS256"|     |    "sub": "1234567890",   |     |    base64url(header) |
  |    "typ": "JWT"  |     |    "name": "John Doe",   |     |    + "." +           |
  |  }               |     |    "iat": 1516239022,    |     |    base64url(payload)|
  |                  |     |    "exp": 1516242622,    |     |    , secret          |
  |  Encoded:        |     |    "scope": "read write" |     |  )                   |
  |  base64url(JSON) |     |  }                        |     |                      |
  |                  |     |                           |     |  Proves integrity    |
  |  Specifies the   |     |  Encoded:                |     |  and authenticity    |
  |  algorithm and   |     |  base64url(JSON)         |     |                      |
  |  token type      |     |                           |     |                      |
  |                  |     |  Contains the claims      |     |                      |
  +------------------+     +---------------------------+     +----------------------+
```

---

## Standard JWT Claims

| Claim | Name | Description | Required? |
|-------|------|-------------|-----------|
| `iss` | Issuer | Who issued the token | Recommended |
| `sub` | Subject | Who the token is about (usually user ID) | Recommended |
| `aud` | Audience | Who the token is intended for | Recommended |
| `exp` | Expiration Time | Unix timestamp when the token expires | **Critical** |
| `nbf` | Not Before | Token is not valid before this time | Optional |
| `iat` | Issued At | When the token was issued | Recommended |
| `jti` | JWT ID | Unique identifier for the token | Optional (useful for revocation) |

Custom claims can be added for application-specific data (e.g., `roles`, `scope`, `email`, `org_id`).

---

## How JWT Authentication Works (Step-by-Step)

1. **Client authenticates** with the server (via login form, OAuth flow, etc.).
2. **Server validates credentials** and generates a JWT containing user claims.
3. **Server signs the JWT** using a secret key (HMAC) or a private key (RSA/ECDSA).
4. **Server returns the JWT** to the client.
5. **Client stores the JWT** and includes it in subsequent requests via the `Authorization: Bearer <token>` header.
6. **Server receives the request**, extracts the JWT, and validates it:
   - Verifies the signature (integrity check).
   - Checks the `exp` claim (is the token expired?).
   - Checks the `aud` claim (is this token meant for this service?).
   - Checks the `iss` claim (was this issued by a trusted authority?).
7. **If valid**, the server extracts claims and processes the request. No database lookup needed.

---

## Flow Diagram

```
 CLIENT                              AUTH SERVER                    RESOURCE SERVER
   |                                      |                              |
   | 1. POST /login                       |                              |
   |    { "username": "john",             |                              |
   |      "password": "s3cret" }          |                              |
   | -----------------------------------> |                              |
   |                                      |                              |
   |    +--------------------------------+|                              |
   |    | AUTH SERVER:                    ||                              |
   |    | a. Validate credentials        ||                              |
   |    | b. Build JWT payload:          ||                              |
   |    |    {                           ||                              |
   |    |      "sub": "user-123",       ||                              |
   |    |      "name": "John Doe",      ||                              |
   |    |      "roles": ["admin"],      ||                              |
   |    |      "iat": 1699000000,       ||                              |
   |    |      "exp": 1699003600        ||                              |
   |    |    }                           ||                              |
   |    | c. Sign with private key       ||                              |
   |    +--------------------------------+|                              |
   |                                      |                              |
   | 2. 200 OK                           |                              |
   |    { "token": "eyJhbGci..." }       |                              |
   | <----------------------------------- |                              |
   |                                      |                              |
   | [Client stores token]               |                              |
   |                                      |                              |
   | 3. GET /api/admin/dashboard          |                              |
   |    Authorization: Bearer eyJhbGci... |                              |
   | ------------------------------------------------------------------> |
   |                                      |                              |
   |    +-------------------------------------------------------+       |
   |    | RESOURCE SERVER (no DB call needed!):                  |       |
   |    |                                                        |       |
   |    | a. Split token on "."                                  |       |
   |    |    [header].[payload].[signature]                      |       |
   |    |                                                        |       |
   |    | b. Verify signature using public key                   |       |
   |    |    VERIFY(header + "." + payload, signature, pub_key)  |       |
   |    |                                                        |       |
   |    | c. Decode payload (base64url -> JSON)                  |       |
   |    |                                                        |       |
   |    | d. Validate claims:                                    |       |
   |    |    - exp > current_time?  YES -> not expired           |       |
   |    |    - aud == "this-service"?  YES -> correct audience   |       |
   |    |    - iss == "auth-server"?  YES -> trusted issuer      |       |
   |    |                                                        |       |
   |    | e. Extract: sub="user-123", roles=["admin"]            |       |
   |    |    User has admin role -> grant access                 |       |
   |    +-------------------------------------------------------+       |
   |                                      |                              |
   | 4. 200 OK                           |                              |
   |    { "dashboard": "..." }           |                              |
   | <------------------------------------------------------------------ |


   Stateless Verification (Key Advantage):

   +-------------------------------------------------------------------+
   |                                                                    |
   |  TRADITIONAL SESSION:          JWT:                                |
   |                                                                    |
   |  Client --> Server --> DB      Client --> Server                   |
   |  (lookup session)              (verify signature locally)          |
   |                                                                    |
   |  Every request = DB query      Every request = CPU computation     |
   |  Requires sticky sessions      Works with any server instance      |
   |  Hard to scale                 Scales horizontally                 |
   |                                                                    |
   +-------------------------------------------------------------------+
```

---

## Signing Algorithms

```
  SYMMETRIC (Shared Secret)              ASYMMETRIC (Key Pair)
  +------------------------------+       +----------------------------------+
  |  Algorithm: HS256, HS384,    |       |  Algorithm: RS256, RS384,       |
  |             HS512             |       |             RS512, ES256,       |
  |                              |       |             ES384, ES512,       |
  |  Same key signs AND verifies |       |             PS256, EdDSA        |
  |                              |       |                                  |
  |  +-------+                   |       |  +-------------+  +----------+  |
  |  |Secret |--- SIGN ------+  |       |  |Private Key  |  |Public Key|  |
  |  |Key    |--- VERIFY ----+  |       |  |  (sign)     |  | (verify) |  |
  |  +-------+                   |       |  +-------------+  +----------+  |
  |                              |       |                                  |
  |  Pros:                       |       |  Pros:                           |
  |  - Fast                      |       |  - Issuer and verifier are       |
  |  - Simple                    |       |    decoupled                     |
  |                              |       |  - Public key can be shared      |
  |  Cons:                       |       |    freely (JWKS endpoint)        |
  |  - Secret must be shared     |       |  - Multiple services can verify  |
  |    with all verifiers        |       |    without knowing the secret    |
  |  - If any verifier is        |       |                                  |
  |    compromised, all are      |       |  Cons:                           |
  |                              |       |  - Slower than HMAC              |
  |  Best for:                   |       |  - Larger key sizes              |
  |  - Single-service systems    |       |                                  |
  |                              |       |  Best for:                       |
  |                              |       |  - Distributed / microservice    |
  |                              |       |    architectures                 |
  +------------------------------+       +----------------------------------+
```

---

## Pros and Cons

| Pros | Cons |
|------|------|
| Stateless -- no server-side session storage needed | Cannot be revoked before expiration (without extra infrastructure) |
| Self-contained -- carries all necessary claims | Payload is not encrypted (only signed) -- do not store secrets in it |
| Scales horizontally -- any server can validate | Token size grows with more claims (header overhead per request) |
| Decoupled issuer/verifier with asymmetric signing | Vulnerable to algorithm confusion attacks if not properly validated |
| Standard format (RFC 7519) with broad library support | Developers often misuse JWTs (no expiration, sensitive data in payload) |
| Works across domains and platforms | Clock skew between servers can cause validation failures |
| Can be used for authentication AND authorization | Long-lived JWTs are dangerous if compromised |

---

## Real-World Use Cases

- **Stateless API authentication** -- Most modern REST and GraphQL APIs use JWTs as access tokens.
- **OAuth 2.0 access tokens** -- Many OAuth providers issue JWTs as access tokens (Auth0, Okta, Azure AD).
- **OpenID Connect ID tokens** -- The identity token in OIDC is always a JWT.
- **Microservice communication** -- Services validate JWTs locally without calling a central auth service.
- **Single Sign-On (SSO)** -- JWTs propagate authentication state across multiple services.
- **Passwordless authentication** -- Magic link emails contain JWTs for one-time authentication.
- **Email verification and password reset** -- Short-lived JWTs encode the action and target user.

---

## When to Use

- You need stateless, scalable authentication for APIs.
- You are building a distributed system where multiple services need to verify authentication.
- You want to avoid server-side session storage.
- You need to pass claims (roles, permissions, user data) within the token itself.
- You are implementing OAuth 2.0 or OpenID Connect.

## When NOT to Use

- You need the ability to immediately revoke individual sessions (use server-side sessions or opaque tokens).
- You need to store sensitive data that should not be visible to the client (JWT payload is readable by anyone).
- Token size is a concern (e.g., very constrained network environments).
- You have a simple, single-server application where sessions work fine.
- You need very long-lived tokens (JWTs should be short-lived).

---

## Security Considerations

### 1. Always Validate the Algorithm
Never trust the `alg` header from the token. Explicitly specify which algorithms your server accepts. The "algorithm none" attack tricks servers into accepting unsigned tokens.

```python
# BAD - trusts whatever algorithm the token claims
payload = jwt.decode(token)

# GOOD - explicitly specifies accepted algorithms
payload = jwt.decode(token, key, algorithms=["RS256"])
```

### 2. Set Short Expiration Times
Access token JWTs should expire in **5-60 minutes**. Use refresh tokens for longer sessions. The shorter the lifetime, the smaller the window of exposure if a token is compromised.

### 3. Validate All Critical Claims
Always validate: `exp`, `iss`, `aud`, and `nbf`. Do not skip any of these checks.

### 4. Do Not Store Sensitive Data in the Payload
The payload is Base64url-encoded, not encrypted. Anyone with the token can read it. Never include passwords, SSNs, credit card numbers, or other secrets.

### 5. Use Asymmetric Keys in Distributed Systems
In microservice architectures, use RS256 or ES256 so that only the auth server has the private key, and all other services verify with the public key.

### 6. Implement Token Revocation (When Needed)
For scenarios requiring immediate revocation:
- Maintain a **blocklist** of revoked token IDs (`jti` claim).
- Use very short-lived tokens (reduces the need for revocation).
- Combine JWTs with a lightweight session check for critical operations.

### 7. Protect Against Token Leakage
- Transmit tokens only over HTTPS.
- Never include tokens in URLs.
- Set appropriate CORS policies.
- Use HTTP-only cookies when possible for browser-based apps.

---

## JWT vs. Opaque Tokens

| Feature | JWT (Self-Contained) | Opaque Token |
|---------|---------------------|--------------|
| Server-side storage | Not required | Required (token-to-data mapping) |
| Validation | Local (signature verification) | Remote (introspection endpoint) |
| Revocation | Difficult (need blocklist) | Easy (delete from store) |
| Scalability | Excellent (no DB calls) | Requires shared data store |
| Payload visibility | Readable by client | Opaque to client |
| Token size | Larger (contains claims) | Smaller (just an ID) |
| Network dependency | None for validation | Requires auth server availability |
| Best for | Distributed systems | Monoliths, when revocation is critical |

---

## JWE: Encrypted JWTs

When the payload must be confidential (not just tamper-proof), use JWE (JSON Web Encryption, RFC 7516):

```
  JWS (Signed Only):
  +------------------------------------------------------------------+
  | Header . Payload . Signature                                      |
  | (readable)  (readable)  (integrity proof)                        |
  +------------------------------------------------------------------+

  JWE (Encrypted):
  +------------------------------------------------------------------+
  | Header . Encrypted Key . IV . Ciphertext . Auth Tag               |
  | (readable)  (encrypted)  (random)  (encrypted payload)  (integrity)|
  +------------------------------------------------------------------+

  Can also combine: Sign THEN Encrypt (nested JWT)
  - Sign the payload first (JWS)
  - Encrypt the entire JWS (JWE)
  - Recipient decrypts, then verifies signature
```

---

## Common Mistakes

| Mistake | Impact | Fix |
|---------|--------|-----|
| No `exp` claim | Token valid forever | Always set expiration |
| Using `HS256` with public key material | Attacker can forge tokens | Use `RS256`/`ES256` for distributed systems |
| Storing tokens in `localStorage` | XSS can steal tokens | Use HTTP-only cookies or in-memory storage |
| Trusting the `alg` header | Algorithm confusion attacks | Hardcode accepted algorithms |
| Putting secrets in the payload | Data exposure | Use JWE or keep secrets server-side |
| Very long expiration times | Extended compromise window | Keep access tokens short-lived (5-60 min) |
| Not validating `iss` and `aud` | Token misuse across services | Always validate issuer and audience |

---

## Summary

JWTs are a powerful, standardized mechanism for stateless authentication and claims-based authorization. Their self-contained nature makes them ideal for distributed systems where multiple services need to independently verify authentication without calling a central authority. However, JWTs come with trade-offs: they are harder to revoke, their payload is readable (not encrypted by default), and they require careful implementation to avoid security pitfalls. Use short expiration times, validate all claims, choose the right signing algorithm, and never store sensitive data in the payload.

---

*Previous: [OAuth 2.0](./04-oauth2.md) | Next: [Access and Refresh Tokens](./06-access-refresh-tokens.md)*
