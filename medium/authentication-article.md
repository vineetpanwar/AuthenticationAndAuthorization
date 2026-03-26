# Authentication Explained: Basic Auth, Bearer Tokens, API Keys, OAuth2, JWT, SSO & Passkeys

Every developer needs to understand authentication. Whether you're building a simple REST API, a mobile app, or a complex enterprise system, choosing the right authentication method is crucial. Get it wrong and you'll face security vulnerabilities, poor user experience, or both.

In this comprehensive guide, we'll break down the **8 most important authentication concepts** every developer should know — from the simplest (Basic Auth) to the most modern (Passkeys). For each one, we'll cover how it works, when to use it, and the trade-offs involved.

By the end, you'll have a clear mental model for choosing the right authentication strategy for any project.

---

## What is Authentication?

Authentication answers one fundamental question: **"Who are you?"**

It's the process of verifying the identity of a user, device, or system before granting access to resources. Think of it as the bouncer at a club checking your ID before letting you in.

Authentication is often confused with **authorization** (which answers "What are you allowed to do?"), but they are distinct concepts. Authentication always comes first.

Here are the 8 methods we'll cover:

| # | Method | Introduced | Complexity |
|---|--------|------------|------------|
| 1 | Basic Authentication | 1996 (HTTP/1.0) | Very Low |
| 2 | Bearer Tokens | 2012 (RFC 6750) | Low |
| 3 | API Keys | Early 2000s | Low |
| 4 | OAuth 2.0 | 2012 (RFC 6749) | High |
| 5 | JSON Web Tokens (JWT) | 2015 (RFC 7519) | Medium |
| 6 | Access & Refresh Tokens | 2012 (with OAuth2) | Medium |
| 7 | Single Sign-On (SSO) | Early 2000s | High |
| 8 | Passkeys (WebAuthn/FIDO2) | 2019+ | Medium |

Let's dive in.

---

## 1. Basic Authentication

**Basic Authentication** is the simplest form of HTTP authentication. It's been around since the early days of the web and is defined in the original HTTP/1.0 specification.

The idea is straightforward: send the username and password with every request.

### How It Works

1. The client combines the username and password into a single string: `username:password`
2. This string is encoded using **Base64** encoding
3. The encoded string is sent in the `Authorization` header of every HTTP request
4. The server decodes the string, extracts the credentials, and verifies them

Here's what it looks like in practice:

```http
GET /api/user/profile HTTP/1.1
Host: api.example.com
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

The value `dXNlcm5hbWU6cGFzc3dvcmQ=` is simply `username:password` encoded in Base64.

**Important:** Base64 is **encoding**, not **encryption**. Anyone who intercepts this header can decode it instantly. This is why Basic Auth **must always be used over HTTPS**.

### The Flow

> **Architecture Diagram: Basic Authentication Flow**
> *Reference: diagrams/01-basic-auth.svg*
>
> ```
> Client                          Server
>   |                                |
>   |  1. GET /resource              |
>   |  Authorization: Basic          |
>   |  base64(user:pass)             |
>   | -----------------------------> |
>   |                                |
>   |  2. Decode Base64              |
>   |     Extract user:pass          |
>   |     Verify against DB          |
>   |                                |
>   |  3. 200 OK (or 401)           |
>   | <----------------------------- |
>   |                                |
> ```
>
> The client sends credentials with **every single request**. There is no session, no token — just raw credentials each time.

### Server-Side Verification

When the server receives a Basic Auth request, it typically:

```javascript
// Express.js middleware example
function basicAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Decode the Base64 string
  const base64Credentials = authHeader.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('utf8');
  const [username, password] = credentials.split(':');

  // Verify against database
  const user = await db.users.findByUsername(username);
  if (!user || !await bcrypt.compare(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  req.user = user;
  next();
}
```

### Pros & Cons

| Pros | Cons |
|------|------|
| Extremely simple to implement | Credentials sent with every request |
| Supported by virtually all HTTP clients | Base64 is not encryption — easily decoded |
| No session management needed | No built-in logout mechanism |
| Great for quick prototyping | Password exposed if not using HTTPS |
| Works with any programming language | Not suitable for browser-based apps (no CSRF protection) |

### When to Use Basic Auth

- **Internal tools and scripts** where simplicity matters
- **Server-to-server communication** over HTTPS in trusted networks
- **Quick prototyping** when you need auth fast
- **API testing** during development

**Avoid** for: Production web applications, mobile apps, anything exposed to the public internet without additional security layers.

### Security Tip

If you must use Basic Auth, always:
1. Use HTTPS (TLS) — never send credentials over plain HTTP
2. Rate-limit authentication attempts to prevent brute-force attacks
3. Store passwords as salted hashes (bcrypt, scrypt, or Argon2)
4. Consider adding IP whitelisting as an additional layer

---

## 2. Bearer Tokens

**Bearer Tokens** are a step up from Basic Auth. Instead of sending credentials with every request, the client first authenticates once and receives a **token**. This token is then sent with subsequent requests.

The name "bearer" means: *whoever bears (holds) this token gets access*. It's like a concert ticket — anyone holding the ticket gets in, regardless of who originally purchased it.

### How It Works

1. The client sends credentials (username/password) to an authentication endpoint
2. The server verifies the credentials and generates a **token**
3. The server returns the token to the client
4. The client includes this token in the `Authorization` header of all subsequent requests
5. The server validates the token on each request

```http
POST /api/login HTTP/1.1
Content-Type: application/json

{
  "username": "developer@example.com",
  "password": "securePassword123"
}
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600
}
```

Subsequent requests:

```http
GET /api/user/profile HTTP/1.1
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### The Flow

> **Architecture Diagram: Bearer Token Flow**
> *Reference: diagrams/02-bearer-tokens.svg*
>
> ```
> Client                     Auth Server              Resource Server
>   |                            |                          |
>   | 1. POST /login             |                          |
>   |    (credentials)           |                          |
>   | -------------------------> |                          |
>   |                            |                          |
>   | 2. Token                   |                          |
>   | <------------------------- |                          |
>   |                            |                          |
>   | 3. GET /resource           |                          |
>   |    Authorization: Bearer   |                          |
>   |    <token>                 |                          |
>   | -------------------------------------------------->  |
>   |                            |                          |
>   |                            |  4. Validate token       |
>   |                            |                          |
>   | 5. 200 OK (resource)       |                          |
>   | <--------------------------------------------------- |
> ```

### Token Types

Bearer tokens can be:

- **Opaque tokens**: Random strings that the server stores and looks up (stateful)
- **Self-contained tokens**: Tokens that carry all necessary information within them (like JWTs — covered in section 5)

```javascript
// Opaque token example
const token = crypto.randomBytes(32).toString('hex');
// Result: "a3f5b8c2d1e4f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"

// Self-contained token (JWT) example
const token = jwt.sign({ userId: 123, role: 'admin' }, SECRET_KEY, { expiresIn: '1h' });
```

### Pros & Cons

| Pros | Cons |
|------|------|
| Credentials sent only once | Token must be stored securely on client |
| Tokens can have expiration times | If token is stolen, attacker has access |
| Works well for APIs and SPAs | No built-in revocation for self-contained tokens |
| Stateless (with self-contained tokens) | Bearer = anyone with the token gets access |
| Widely supported across platforms | Requires HTTPS to prevent token interception |

### When to Use Bearer Tokens

- **REST APIs** that need stateless authentication
- **Single Page Applications (SPAs)** after initial login
- **Mobile applications** that need to maintain sessions
- **Microservice-to-microservice communication**

### Security Best Practices

1. **Always use HTTPS** — tokens are sensitive
2. **Set short expiration times** — combine with refresh tokens (section 6)
3. **Store tokens securely** — use `httpOnly` cookies or secure storage, never `localStorage`
4. **Implement token revocation** — maintain a blacklist for compromised tokens

---

## 3. API Keys

**API Keys** are unique identifiers used to authenticate applications (not users) making API requests. They're like a building access card — they identify which tenant you are, but not necessarily which individual person.

### How It Works

1. A developer registers an application with the API provider
2. The provider generates a unique **API key** for that application
3. The developer includes this key in API requests
4. The server identifies the application and enforces rate limits, quotas, and permissions

API keys can be sent in several ways:

**In the header:**
```http
GET /api/weather?city=London HTTP/1.1
X-API-Key: sk_test_abc123def456ghi789
```

**As a query parameter:**
```http
GET /api/weather?city=London&api_key=sk_test_abc123def456ghi789
```

**In the request body:**
```json
{
  "api_key": "sk_test_abc123def456ghi789",
  "city": "London"
}
```

### The Flow

> **Architecture Diagram: API Key Flow**
> *Reference: diagrams/03-api-keys.svg*
>
> ```
> Developer                   API Provider
>   |                              |
>   | 1. Register Application      |
>   | ---------------------------> |
>   |                              |
>   | 2. API Key: sk_test_abc123   |
>   | <--------------------------- |
>   |                              |
>
> Application                  API Server
>   |                              |
>   | 3. GET /resource             |
>   |    X-API-Key: sk_test_abc123 |
>   | ---------------------------> |
>   |                              |
>   | 4. Identify app              |
>   |    Check rate limits         |
>   |    Check permissions         |
>   |                              |
>   | 5. 200 OK (data)             |
>   | <--------------------------- |
> ```

### Key Naming Conventions

Many providers use prefixes to distinguish key types:

- `sk_test_` — Secret key for production (Stripe)
- `sk_test_` — Secret key for testing (Stripe)
- `pk_live_` — Publishable key for production
- `AKIA...` — AWS Access Key ID
- `AIza...` — Google API Key

### Pros & Cons

| Pros | Cons |
|------|------|
| Very simple to implement and use | Not tied to a user — identifies the app |
| Great for rate limiting and usage tracking | If leaked, hard to determine scope of damage |
| Easy to rotate and revoke | Often accidentally committed to version control |
| No complex handshake required | Doesn't authenticate users, only applications |
| Perfect for public APIs | Can be easily shared or stolen |

### When to Use API Keys

- **Public APIs** where you need to track usage (Google Maps, OpenWeather)
- **Rate limiting** per application
- **Usage billing** (track how many requests each customer makes)
- **Identifying** which application is making requests

**Avoid** for: User authentication, any scenario where you need to know *who* the user is (not just *which app*).

### Security Best Practices

1. **Never commit API keys to version control** — use environment variables
2. **Use different keys for development and production**
3. **Implement key rotation** — regularly generate new keys and deprecate old ones
4. **Restrict key permissions** — limit what each key can access
5. **Use server-side only** — never expose secret keys in frontend code

```bash
# Bad: Hardcoded in source
API_KEY="sk_test_abc123def456"

# Good: Environment variable
export API_KEY="sk_test_abc123def456"
# Or use .env files with dotenv
```

---

## 4. OAuth 2.0

**OAuth 2.0** is the industry-standard protocol for **authorization** (and, by extension, authentication via OpenID Connect). It's what powers "Sign in with Google," "Login with GitHub," and countless other third-party login flows.

OAuth 2.0 solves a critical problem: **How can you let a third-party application access your data without giving it your password?**

### The Core Concept

Imagine you want to let a photo printing service access your Google Photos. Without OAuth, you'd have to give the printing service your Google password. That's terrible for security.

With OAuth 2.0, you grant the printing service **limited, revocable access** to your Google Photos — without ever sharing your password.

### Key Terminology

Before diving in, let's define the players:

- **Resource Owner**: The user (you) who owns the data
- **Client**: The application requesting access (photo printing service)
- **Authorization Server**: The server that authenticates the user and issues tokens (Google's auth server)
- **Resource Server**: The server hosting the protected data (Google Photos API)
- **Scope**: The specific permissions being requested (e.g., `photos.readonly`)
- **Redirect URI**: Where the user is sent after granting/denying access
- **Authorization Code**: A temporary code exchanged for an access token

### How It Works: Authorization Code Flow

This is the most common and most secure OAuth 2.0 flow:

**Step 1: Authorization Request**

The client redirects the user to the authorization server:

```
https://accounts.google.com/o/oauth2/v2/auth?
  response_type=code
  &client_id=YOUR_CLIENT_ID
  &redirect_uri=https://printservice.com/callback
  &scope=https://www.googleapis.com/auth/photoslibrary.readonly
  &state=random_csrf_token
```

**Step 2: User Consent**

Google shows a consent screen: "PrintService wants to view your Google Photos. Allow?"

**Step 3: Authorization Code**

If the user approves, Google redirects back to the client with an authorization code:

```
https://printservice.com/callback?code=AUTH_CODE_HERE&state=random_csrf_token
```

**Step 4: Token Exchange**

The client exchanges the authorization code for an access token (server-to-server):

```http
POST /token HTTP/1.1
Host: oauth2.googleapis.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTH_CODE_HERE
&redirect_uri=https://printservice.com/callback
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
```

**Step 5: Access Resource**

The client uses the access token to access the user's photos:

```http
GET /v1/mediaItems HTTP/1.1
Host: photoslibrary.googleapis.com
Authorization: Bearer ACCESS_TOKEN_HERE
```

### The Flow

> **Architecture Diagram: OAuth 2.0 Authorization Code Flow**
> *Reference: diagrams/04-oauth2.svg*
>
> ```
> User        Client App       Auth Server       Resource Server
>  |              |                 |                    |
>  | 1. Click     |                 |                    |
>  |  "Login"     |                 |                    |
>  | -----------> |                 |                    |
>  |              |                 |                    |
>  |  2. Redirect to Auth Server   |                    |
>  | <----------- |                 |                    |
>  |              |                 |                    |
>  | 3. Login & Consent            |                    |
>  | ----------------------------> |                    |
>  |              |                 |                    |
>  | 4. Redirect with Auth Code    |                    |
>  | <---------------------------- |                    |
>  |              |                 |                    |
>  | 5. Send Auth Code             |                    |
>  | -----------> |                 |                    |
>  |              |                 |                    |
>  |              | 6. Exchange     |                    |
>  |              |    code for     |                    |
>  |              |    token        |                    |
>  |              | --------------> |                    |
>  |              |                 |                    |
>  |              | 7. Access Token |                    |
>  |              | <-------------- |                    |
>  |              |                 |                    |
>  |              | 8. GET /resource (with token)        |
>  |              | ----------------------------------->  |
>  |              |                 |                    |
>  |              | 9. Protected Resource               |
>  |              | <----------------------------------- |
>  |              |                 |                    |
>  | 10. Show     |                 |                    |
>  |   resource   |                 |                    |
>  | <----------- |                 |                    |
> ```

### Other OAuth 2.0 Flows

**Client Credentials Flow** — For server-to-server communication (no user involved):

```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
&scope=api.read
```

**PKCE (Proof Key for Code Exchange)** — For public clients like mobile apps and SPAs that can't securely store a client secret:

```javascript
// 1. Generate a random code_verifier
const codeVerifier = generateRandomString(128);

// 2. Create code_challenge from the verifier
const codeChallenge = base64UrlEncode(sha256(codeVerifier));

// 3. Include code_challenge in the authorization request
// 4. Include code_verifier when exchanging the code for a token
```

**Device Code Flow** — For devices without a browser (smart TVs, IoT):

```
1. Device shows: "Go to https://example.com/device and enter code: ABCD-1234"
2. User opens browser on phone, enters code
3. User logs in and approves
4. Device polls the auth server and eventually receives a token
```

### Pros & Cons

| Pros | Cons |
|------|------|
| User never shares password with third-party | Complex to implement from scratch |
| Granular permissions via scopes | Many moving parts and redirect flows |
| Tokens are revocable | Vulnerable to redirect URI attacks if misconfigured |
| Industry standard with massive ecosystem | Requires HTTPS everywhere |
| Supports multiple flows for different clients | Access tokens can be intercepted |
| Separation of auth server and resource server | Token storage is the client's responsibility |

### When to Use OAuth 2.0

- **"Sign in with X"** (Google, GitHub, Facebook, etc.)
- **Third-party API access** (letting other apps access your users' data)
- **Mobile and SPA authentication** (with PKCE)
- **Microservice architectures** (client credentials flow)

### OAuth 2.0 vs OAuth 2.1

OAuth 2.1 is an in-progress update that consolidates best practices:
- **PKCE is required** for all clients (not just public ones)
- **Implicit flow is removed** (it was insecure)
- **Resource Owner Password Credentials flow is removed**
- Refresh tokens must be **sender-constrained** or **one-time use**

---

## 5. JSON Web Tokens (JWT)

**JSON Web Tokens (JWT, pronounced "jot")** are a compact, self-contained way to transmit information between parties as a JSON object. They're the most popular token format used in modern web authentication.

### The Three-Part Structure

A JWT consists of three parts separated by dots: `xxxxx.yyyyy.zzzzz`

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Let's decode each part:

**Part 1: Header** (algorithm and token type)

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Part 2: Payload** (the claims — the actual data)

```json
{
  "sub": "1234567890",
  "name": "John Doe",
  "email": "john@example.com",
  "role": "admin",
  "iat": 1516239022,
  "exp": 1516242622
}
```

**Part 3: Signature** (verifies the token hasn't been tampered with)

```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

### How It Works

1. User logs in with credentials
2. Server validates credentials and creates a JWT containing user claims
3. Server signs the JWT with a secret key (HMAC) or private key (RSA/ECDSA)
4. Server returns the JWT to the client
5. Client sends the JWT with every request
6. Server verifies the signature and reads the claims — **no database lookup needed**

```javascript
// Creating a JWT (server-side)
const jwt = require('jsonwebtoken');

const token = jwt.sign(
  {
    sub: user.id,
    name: user.name,
    email: user.email,
    role: user.role
  },
  process.env.JWT_SECRET,
  { expiresIn: '1h' }
);

// Verifying a JWT (server-side)
try {
  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  console.log(decoded.sub);  // "1234567890"
  console.log(decoded.role); // "admin"
} catch (err) {
  console.error('Invalid token:', err.message);
}
```

### The Flow

> **Architecture Diagram: JWT Authentication Flow**
> *Reference: diagrams/05-jwt.svg*
>
> ```
> Client                          Server
>   |                                |
>   | 1. POST /login                 |
>   |    { email, password }         |
>   | -----------------------------> |
>   |                                |
>   |  2. Validate credentials       |
>   |     Create JWT with claims     |
>   |     Sign with secret key       |
>   |                                |
>   | 3. { token: "eyJ..." }         |
>   | <----------------------------- |
>   |                                |
>   | 4. GET /api/profile            |
>   |    Authorization: Bearer eyJ.. |
>   | -----------------------------> |
>   |                                |
>   |  5. Verify signature           |
>   |     Decode claims              |
>   |     (NO database lookup!)      |
>   |                                |
>   | 6. 200 OK { user data }        |
>   | <----------------------------- |
> ```

### Standard JWT Claims

| Claim | Name | Description |
|-------|------|-------------|
| `sub` | Subject | Who the token is about (usually user ID) |
| `iss` | Issuer | Who created and signed the token |
| `aud` | Audience | Who the token is intended for |
| `exp` | Expiration | When the token expires (Unix timestamp) |
| `iat` | Issued At | When the token was created |
| `nbf` | Not Before | Token is not valid before this time |
| `jti` | JWT ID | Unique identifier for the token |

### Signing Algorithms

| Algorithm | Type | Use Case |
|-----------|------|----------|
| HS256 | Symmetric (shared secret) | Single server, simple setups |
| RS256 | Asymmetric (public/private key) | Distributed systems, microservices |
| ES256 | Asymmetric (elliptic curve) | Performance-sensitive, modern systems |

### Pros & Cons

| Pros | Cons |
|------|------|
| Stateless — no server-side session storage | Cannot be revoked before expiration (without a blacklist) |
| Self-contained — carries all user info | Payload is readable by anyone (not encrypted by default) |
| Compact — small size for HTTP headers | Token size grows with more claims |
| Works across domains and services | Vulnerable to XSS if stored in localStorage |
| Strong ecosystem and library support | Secret key compromise = total system compromise |
| Can be verified without contacting the issuer | Clock skew between servers can cause issues |

### When to Use JWT

- **Stateless API authentication** — the most common use case
- **Microservices** — one service issues the JWT, others verify it independently
- **Single Sign-On** — carry user identity across services
- **Information exchange** — securely transmit claims between parties

### Common JWT Mistakes (And How to Avoid Them)

1. **Storing JWTs in localStorage** — Use `httpOnly`, `Secure` cookies instead
2. **Not validating the algorithm** — Always specify the expected algorithm on verification
3. **Using `none` algorithm** — Never accept tokens with `alg: "none"`
4. **Not checking expiration** — Always validate `exp` claim
5. **Putting sensitive data in the payload** — Remember, it's Base64-encoded, not encrypted
6. **Using weak secrets** — Use at least 256 bits of entropy for HMAC secrets

---

## 6. Access & Refresh Tokens

Access tokens expire quickly. Users hate logging in repeatedly. **Refresh tokens** solve this problem by allowing the client to get new access tokens without requiring the user to re-authenticate.

### The Two-Token System

| Token | Purpose | Lifetime | Stored |
|-------|---------|----------|--------|
| **Access Token** | Authenticates API requests | Short (15 min - 1 hour) | Memory or secure cookie |
| **Refresh Token** | Gets new access tokens | Long (days to months) | Secure, httpOnly cookie |

### How It Works

1. User logs in with credentials
2. Server returns both an **access token** and a **refresh token**
3. Client uses the access token for API requests
4. When the access token expires, client sends the refresh token to get a new one
5. Server validates the refresh token and issues a new access token (and optionally a new refresh token)
6. If the refresh token is expired or revoked, the user must log in again

```javascript
// Login response
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "dGhpcyBpcyBhIHJlZnJl...",
  "token_type": "Bearer",
  "expires_in": 900,            // 15 minutes
  "refresh_expires_in": 604800  // 7 days
}
```

### The Flow

> **Architecture Diagram: Access & Refresh Token Flow**
> *Reference: diagrams/06-refresh-tokens.svg*
>
> ```
> Client                          Server                    Database
>   |                                |                          |
>   | 1. POST /login                 |                          |
>   | -----------------------------> |                          |
>   |                                | 2. Validate credentials  |
>   |                                | -----------------------> |
>   |                                |                          |
>   |                                | 3. Store refresh token   |
>   |                                | -----------------------> |
>   |                                |                          |
>   | 4. { access_token,             |                          |
>   |      refresh_token }           |                          |
>   | <----------------------------- |                          |
>   |                                |                          |
>   | 5. GET /api/data               |                          |
>   |    Authorization: Bearer <AT>  |                          |
>   | -----------------------------> |                          |
>   |                                |                          |
>   | 6. 200 OK                      |                          |
>   | <----------------------------- |                          |
>   |                                |                          |
>   | ... time passes, AT expires .. |                          |
>   |                                |                          |
>   | 7. GET /api/data               |                          |
>   |    Authorization: Bearer <AT>  |                          |
>   | -----------------------------> |                          |
>   |                                |                          |
>   | 8. 401 Unauthorized            |                          |
>   | <----------------------------- |                          |
>   |                                |                          |
>   | 9. POST /refresh               |                          |
>   |    { refresh_token }           |                          |
>   | -----------------------------> |                          |
>   |                                | 10. Validate RT          |
>   |                                | -----------------------> |
>   |                                |                          |
>   | 11. { new_access_token,        |                          |
>   |       new_refresh_token }      |                          |
>   | <----------------------------- |                          |
>   |                                |                          |
>   | 12. Retry original request     |                          |
>   |     with new access token      |                          |
>   | -----------------------------> |                          |
> ```

### Token Rotation

**Refresh token rotation** is a security best practice where each time a refresh token is used, a new one is issued and the old one is invalidated:

```javascript
// Server-side refresh logic
async function refreshTokens(oldRefreshToken) {
  // 1. Find the refresh token in the database
  const storedToken = await db.refreshTokens.findOne({ token: oldRefreshToken });

  if (!storedToken) {
    // Token reuse detected! Possible theft.
    // Revoke ALL refresh tokens for this user
    await db.refreshTokens.deleteMany({ userId: storedToken.userId });
    throw new Error('Refresh token reuse detected');
  }

  // 2. Invalidate the old refresh token
  await db.refreshTokens.deleteOne({ token: oldRefreshToken });

  // 3. Generate new tokens
  const newAccessToken = generateAccessToken(storedToken.userId);
  const newRefreshToken = generateRefreshToken();

  // 4. Store the new refresh token
  await db.refreshTokens.insertOne({
    token: newRefreshToken,
    userId: storedToken.userId,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
  });

  return { accessToken: newAccessToken, refreshToken: newRefreshToken };
}
```

### Pros & Cons

| Pros | Cons |
|------|------|
| Users stay logged in without re-authenticating | More complex implementation |
| Short-lived access tokens limit damage if stolen | Refresh tokens must be stored securely (server-side) |
| Refresh tokens can be revoked | Token rotation adds complexity |
| Supports "remember me" functionality | Requires a database for refresh token storage |
| Industry standard approach | Clock synchronization matters |

### When to Use Access & Refresh Tokens

- **Any application where users expect persistent sessions** (most web and mobile apps)
- **SPAs and mobile apps** where you want to avoid frequent re-logins
- **OAuth 2.0 implementations** (refresh tokens are part of the spec)

---

## 7. Single Sign-On (SSO)

**Single Sign-On (SSO)** lets users log in once and gain access to multiple applications without re-authenticating. Think about how logging into Gmail automatically gives you access to YouTube, Google Drive, Google Calendar, and every other Google service.

### How It Works

SSO uses a **centralized identity provider (IdP)** that all applications trust. When you log in to any application, it redirects you to the IdP. If you've already authenticated with the IdP, you're immediately redirected back with proof of authentication — no second login required.

### SSO Protocols

The two main protocols for implementing SSO are:

**SAML 2.0 (Security Assertion Markup Language)**
- Uses XML-based assertions
- Common in enterprise environments
- Transmitted via browser redirects (POST bindings)

**OIDC (OpenID Connect)**
- Built on top of OAuth 2.0
- Uses JSON/JWT
- More modern, lighter weight, developer-friendly
- Common in consumer and modern enterprise apps

### The Flow (OIDC-based SSO)

> **Architecture Diagram: SSO Flow**
> *Reference: diagrams/07-sso.svg*
>
> ```
> User        App A          Identity Provider       App B
>  |            |                   |                   |
>  | 1. Visit   |                   |                   |
>  |   App A    |                   |                   |
>  | ---------> |                   |                   |
>  |            |                   |                   |
>  |  2. Redirect to IdP           |                   |
>  | <--------- |                   |                   |
>  |            |                   |                   |
>  | 3. Login (username/password)  |                   |
>  | -----------------------------> |                   |
>  |            |                   |                   |
>  | 4. IdP creates session        |                   |
>  |    + issues ID token          |                   |
>  |            |                   |                   |
>  | 5. Redirect back to App A     |                   |
>  |    with ID token              |                   |
>  | <----------------------------- |                   |
>  |            |                   |                   |
>  | 6. App A validates token      |                   |
>  |    and creates local session  |                   |
>  | ---------> |                   |                   |
>  |            |                   |                   |
>  | 7. Logged in to App A!        |                   |
>  | <--------- |                   |                   |
>  |            |                   |                   |
>  |            |                   |                   |
>  | 8. Visit App B                |                   |
>  | ------------------------------------------------> |
>  |            |                   |                   |
>  | 9. Redirect to IdP            |                   |
>  | <------------------------------------------------ |
>  |            |                   |                   |
>  | 10. IdP detects existing      |                   |
>  |     session — NO login needed!|                   |
>  | -----------------------------> |                   |
>  |            |                   |                   |
>  | 11. Redirect back to App B    |                   |
>  |     with ID token             |                   |
>  | <----------------------------- |                   |
>  |            |                   |                   |
>  | 12. Logged in to App B!       |                   |
>  |     (without typing password) |                   |
>  | ------------------------------------------------> |
> ```

### SAML vs OIDC Comparison

| Feature | SAML 2.0 | OIDC |
|---------|----------|------|
| Format | XML | JSON/JWT |
| Transport | HTTP POST/Redirect | HTTP Redirect |
| Token Type | SAML Assertion | ID Token (JWT) |
| Complexity | High | Medium |
| Best For | Enterprise, legacy | Modern apps, mobile |
| Common Providers | Okta, OneLogin, ADFS | Google, Auth0, Keycloak |

### Identity Providers

Popular IdP solutions include:

- **Enterprise**: Okta, Azure AD, OneLogin, Ping Identity
- **Open Source**: Keycloak, Authentik, Casdoor
- **Cloud**: Auth0, Firebase Auth, AWS Cognito, Google Identity Platform

### Pros & Cons

| Pros | Cons |
|------|------|
| One login for all applications | Complex to set up initially |
| Improved user experience | Single point of failure (IdP goes down = everything down) |
| Centralized user management | Requires trust between all parties |
| Easier to enforce security policies | SAML is complex and XML-heavy |
| Reduces password fatigue | Vendor lock-in with commercial IdPs |
| Simplifies onboarding/offboarding | Session management across apps is tricky |

### When to Use SSO

- **Enterprise environments** with multiple internal applications
- **SaaS products** that want "Login with Okta/Azure AD" for enterprise customers
- **Consumer apps** wanting "Sign in with Google/Apple/Facebook"
- **Microservice architectures** sharing authentication

---

## 8. Passkeys (WebAuthn/FIDO2)

**Passkeys** are the newest and most exciting authentication method on this list. They aim to replace passwords entirely with cryptographic key pairs tied to your device. Major tech companies — Apple, Google, and Microsoft — are all pushing passkeys as the future of authentication.

### The Problem with Passwords

- 81% of data breaches involve weak or stolen passwords (Verizon DBIR)
- Users reuse passwords across sites
- Phishing attacks trick users into revealing passwords
- Password managers add friction and aren't universally adopted

Passkeys solve all of these problems.

### How Passkeys Work

Passkeys use **public-key cryptography**:

1. **Registration**: Your device generates a unique key pair (public key + private key) for each website
2. **Private key**: Stays on your device, never leaves, protected by biometrics (fingerprint, face) or device PIN
3. **Public key**: Sent to the server and stored
4. **Authentication**: The server sends a challenge, your device signs it with the private key, the server verifies with the public key

**There is no password. There is nothing to phish. There is nothing to leak.**

### The Registration Flow

```javascript
// 1. Server generates a challenge
const registrationOptions = {
  challenge: new Uint8Array(32), // Random bytes
  rp: { name: "Example Corp", id: "example.com" },
  user: {
    id: new Uint8Array(16),
    name: "user@example.com",
    displayName: "John Doe"
  },
  pubKeyCredParams: [
    { alg: -7, type: "public-key" },   // ES256
    { alg: -257, type: "public-key" }  // RS256
  ],
  authenticatorSelection: {
    authenticatorAttachment: "platform",  // Built-in (Touch ID, Windows Hello)
    residentKey: "required",
    userVerification: "required"
  }
};

// 2. Browser/OS prompts for biometric verification
const credential = await navigator.credentials.create({
  publicKey: registrationOptions
});

// 3. Send the public key to the server for storage
await fetch('/api/register-passkey', {
  method: 'POST',
  body: JSON.stringify({
    id: credential.id,
    rawId: credential.rawId,
    response: {
      attestationObject: credential.response.attestationObject,
      clientDataJSON: credential.response.clientDataJSON
    }
  })
});
```

### The Authentication Flow

```javascript
// 1. Server sends a challenge
const authOptions = await fetch('/api/passkey-challenge').then(r => r.json());

// 2. Browser/OS prompts for biometric verification
const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: authOptions.challenge,
    rpId: "example.com",
    allowCredentials: [] // Empty for discoverable credentials
  }
});

// 3. Send the signed challenge to the server
const result = await fetch('/api/verify-passkey', {
  method: 'POST',
  body: JSON.stringify({
    id: assertion.id,
    response: {
      authenticatorData: assertion.response.authenticatorData,
      clientDataJSON: assertion.response.clientDataJSON,
      signature: assertion.response.signature
    }
  })
});
```

### The Flow

> **Architecture Diagram: Passkey (WebAuthn) Authentication Flow**
> *Reference: diagrams/08-passkeys.svg*
>
> ```
> User          Device/Browser       Server
>  |                 |                  |
>  | 1. "Sign in"    |                  |
>  | --------------> |                  |
>  |                 |                  |
>  |                 | 2. Request       |
>  |                 |    challenge     |
>  |                 | ---------------> |
>  |                 |                  |
>  |                 | 3. Challenge     |
>  |                 | <--------------- |
>  |                 |                  |
>  | 4. Biometric    |                  |
>  |    prompt       |                  |
>  |    (Touch ID /  |                  |
>  |     Face ID)    |                  |
>  | --------------> |                  |
>  |                 |                  |
>  |                 | 5. Sign          |
>  |                 |    challenge     |
>  |                 |    with private  |
>  |                 |    key           |
>  |                 |                  |
>  |                 | 6. Send signed   |
>  |                 |    response      |
>  |                 | ---------------> |
>  |                 |                  |
>  |                 |  7. Verify with  |
>  |                 |     public key   |
>  |                 |                  |
>  |                 | 8. Authenticated!|
>  |                 | <--------------- |
>  |                 |                  |
>  | 9. Logged in!   |                  |
>  | <-------------- |                  |
> ```

### Cross-Device Authentication

Passkeys can sync across devices:

- **Apple**: Synced via iCloud Keychain across iPhone, iPad, Mac
- **Google**: Synced via Google Password Manager across Android devices and Chrome
- **Microsoft**: Windows Hello with cross-device support
- **Third-party**: 1Password, Dashlane, and other password managers now support passkeys

### Passkeys vs Other Methods

| Feature | Passwords | 2FA (TOTP) | Passkeys |
|---------|-----------|------------|----------|
| Phishing resistant | No | Partially | **Yes** |
| Nothing to remember | No | No | **Yes** |
| Nothing to leak | No | Partially | **Yes** |
| Cross-device | Yes (reused) | No | **Yes (synced)** |
| User experience | Poor | Medium | **Excellent** |
| Server breach impact | Catastrophic | Moderate | **Minimal** |

### Pros & Cons

| Pros | Cons |
|------|------|
| Phishing-proof by design | Relatively new — not universally supported yet |
| Nothing for users to remember | Requires device with biometric capability |
| Stronger than any password | Recovery can be complex if all devices are lost |
| Faster login experience | Users need education on the concept |
| No credentials stored on server (only public keys) | Platform vendor lock-in concerns |
| Built into all major browsers and OSes | Server-side implementation is non-trivial |

### When to Use Passkeys

- **New applications** where you want the best user experience and security
- **Consumer-facing apps** that want to reduce friction
- **High-security applications** (banking, healthcare)
- **As a second factor** alongside existing authentication (transition period)
- **Progressive adoption** — offer passkeys as an option alongside passwords

### Industry Adoption

As of 2025-2026, passkeys are supported by:
- Google, Apple, Microsoft (login to their services)
- GitHub, PayPal, eBay, Best Buy, Kayak
- Major password managers (1Password, Dashlane, Bitwarden)
- All modern browsers (Chrome, Safari, Firefox, Edge)

---

## Comparison Table

Here's a comprehensive comparison of all 8 authentication methods:

| Method | Stateless | Complexity | Security Level | Best For |
|--------|-----------|------------|----------------|----------|
| **Basic Auth** | Yes | Very Low | Low | Internal tools, development |
| **Bearer Tokens** | Depends | Low | Medium | APIs, SPAs |
| **API Keys** | Yes | Low | Low-Medium | Public APIs, rate limiting |
| **OAuth 2.0** | Yes | High | High | Third-party access, social login |
| **JWT** | Yes | Medium | Medium-High | Stateless APIs, microservices |
| **Access/Refresh Tokens** | Hybrid | Medium | High | Persistent sessions |
| **SSO** | No (centralized) | High | High | Enterprise, multi-app systems |
| **Passkeys** | N/A | Medium | Very High | Modern consumer & enterprise apps |

### Security Ranking (Highest to Lowest)

1. **Passkeys** — Phishing-proof, nothing to steal
2. **OAuth 2.0 + PKCE** — Proven, industry-standard
3. **SSO (OIDC)** — Centralized, strong policies
4. **JWT + Refresh Tokens** — Stateless with revocation capability
5. **Bearer Tokens (opaque)** — Server-validated, revocable
6. **API Keys** — Simple but limited
7. **Basic Auth** — Only acceptable over HTTPS with additional safeguards

---

## Decision Tree: Which Authentication Method Should You Choose?

Use this decision tree to guide your choice:

```
START: What are you building?
│
├── Internal tool / prototype?
│   └── Basic Auth (over HTTPS) or API Keys
│
├── Public API for developers?
│   └── API Keys (for identification) + OAuth 2.0 (for user data access)
│
├── SPA or Mobile App?
│   ├── Need third-party login (Google, GitHub)?
│   │   └── OAuth 2.0 + PKCE + JWT
│   └── Own authentication only?
│       └── JWT + Refresh Tokens (consider adding Passkeys)
│
├── Enterprise application?
│   ├── Multiple internal apps?
│   │   └── SSO (OIDC or SAML)
│   └── Single application?
│       └── OAuth 2.0 via corporate IdP (Okta, Azure AD)
│
├── Microservices?
│   └── JWT (service-to-service) + OAuth 2.0 Client Credentials
│
├── Consumer app prioritizing UX?
│   └── Passkeys + OAuth 2.0 social login fallback
│
└── IoT / Device without browser?
    └── OAuth 2.0 Device Code Flow
```

---

## Key Takeaways

- **There is no single "best" authentication method.** The right choice depends on your use case, security requirements, and user experience goals.

- **Basic Auth and API Keys are fine for simple use cases** — internal tools, development, and basic API identification. Just always use HTTPS.

- **OAuth 2.0 is the backbone of modern authentication.** Understanding it deeply will serve you well, regardless of what you build.

- **JWTs are powerful but come with responsibility.** Understand their limitations (no built-in revocation, readable payload) and mitigate them.

- **Refresh tokens solve the UX problem** of short-lived access tokens. Implement token rotation for security.

- **SSO is essential for enterprise** and dramatically improves user experience across multiple applications.

- **Passkeys are the future.** Start supporting them now, even if only as an option alongside existing methods.

- **Layer your security.** Combine methods — e.g., API Keys for identification + OAuth 2.0 for authorization + JWT for stateless verification + refresh tokens for session management.

- **Always use HTTPS.** This isn't optional — every authentication method described here requires encrypted transport.

---

## What's Next?

In the companion article, we dive deep into **Authorization** — RBAC, ABAC, ACL, and how to choose the right model for your application. Authentication tells you *who* the user is; authorization tells you *what they can do*.

Read it here: [Authorization Explained: RBAC, ABAC, ACL & How to Choose the Right Model](#)

---

## References

- Based on concepts from Hayk Simonyan's "7 Authentication Concepts Every Developer Should Know"
- OAuth 2.0 Specification: [RFC 6749](https://tools.ietf.org/html/rfc6749)
- JWT Specification: [RFC 7519](https://tools.ietf.org/html/rfc7519)
- WebAuthn Specification: [W3C Web Authentication](https://www.w3.org/TR/webauthn-2/)
- FIDO Alliance: [Passkeys](https://fidoalliance.org/passkeys/)
- Full code implementations: [GitHub Repository](https://github.com/vineetpanwar/AuthenticationAndAuthorization)

---

*If you found this guide helpful, follow me for more deep dives into security, backend architecture, and developer tools.*
