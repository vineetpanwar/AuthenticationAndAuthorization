# Access and Refresh Tokens

## Introduction

Access tokens and refresh tokens form a two-token architecture that balances **security** and **user experience** in modern authentication systems. This pattern is a core component of OAuth 2.0 (RFC 6749) and is used by virtually every major identity provider (Google, Microsoft, Auth0, Okta, AWS Cognito).

The fundamental problem they solve: **How do you keep users logged in for days or weeks without creating a long-lived credential that, if stolen, grants unlimited access?**

The answer is to split the concern into two tokens:

- **Access Token** -- Short-lived (minutes), used to access protected resources. If stolen, the attacker has a very limited time window.
- **Refresh Token** -- Long-lived (days to months), used *only* to obtain new access tokens. If stolen, it can be detected and revoked.

This separation of concerns is one of the most important patterns in modern authentication design.

---

## How It Works (Step-by-Step)

1. **User authenticates** (login form, OAuth flow, etc.).
2. **Auth server issues both tokens**: a short-lived access token and a long-lived refresh token.
3. **Client stores both tokens** securely (access token in memory, refresh token in HTTP-only cookie or secure storage).
4. **Client uses the access token** for API requests via the `Authorization: Bearer <access_token>` header.
5. **Access token expires** after a short period (e.g., 15 minutes).
6. **Client detects the expired token** (receives `401 Unauthorized` response).
7. **Client sends the refresh token** to the auth server's token endpoint.
8. **Auth server validates the refresh token** and issues a **new** access token (and optionally a new refresh token).
9. **Client retries the original request** with the new access token.
10. **Process repeats** until the refresh token expires or is revoked.

---

## Flow Diagram

```
 CLIENT                                AUTH SERVER                  RESOURCE SERVER
   |                                        |                             |
   | 1. POST /login                         |                             |
   |    { username, password }              |                             |
   | -------------------------------------> |                             |
   |                                        |                             |
   |    +----------------------------------+|                             |
   |    | AUTH SERVER:                      ||                             |
   |    | a. Validate credentials           ||                             |
   |    | b. Generate access token          ||                             |
   |    |    (expires: 15 minutes)          ||                             |
   |    | c. Generate refresh token         ||                             |
   |    |    (expires: 30 days)             ||                             |
   |    | d. Store refresh token metadata   ||                             |
   |    |    (user_id, device, issued_at)   ||                             |
   |    +----------------------------------+|                             |
   |                                        |                             |
   | 2. 200 OK                             |                             |
   |    {                                   |                             |
   |      "access_token": "eyJhbG...",     |                             |
   |      "refresh_token": "dGhpcyBp...",  |                             |
   |      "token_type": "Bearer",          |                             |
   |      "expires_in": 900                |                             |
   |    }                                   |                             |
   | <------------------------------------- |                             |
   |                                        |                             |
   |  [Store: access_token in memory,       |                             |
   |   refresh_token in HTTP-only cookie]   |                             |
   |                                        |                             |
   |                                        |                             |
   |========== NORMAL OPERATION (0-15 min) ==========================    |
   |                                        |                             |
   | 3. GET /api/data                       |                             |
   |    Authorization: Bearer eyJhbG...     |                             |
   | ----------------------------------------------------------->        |
   |                                        |                             |
   | 4. 200 OK { "data": [...] }           |                             |
   | <-----------------------------------------------------------        |
   |                                        |                             |
   |                                        |                             |
   |========== ACCESS TOKEN EXPIRES (after 15 min) ==================    |
   |                                        |                             |
   | 5. GET /api/data                       |                             |
   |    Authorization: Bearer eyJhbG...     |  (token expired)            |
   | ----------------------------------------------------------->        |
   |                                        |                             |
   | 6. 401 Unauthorized                   |                             |
   |    { "error": "token_expired" }       |                             |
   | <-----------------------------------------------------------        |
   |                                        |                             |
   |                                        |                             |
   |========== TOKEN REFRESH ========================================    |
   |                                        |                             |
   | 7. POST /oauth/token                  |                             |
   |    grant_type=refresh_token            |                             |
   |    refresh_token=dGhpcyBp...          |                             |
   | -------------------------------------> |                             |
   |                                        |                             |
   |    +----------------------------------+|                             |
   |    | AUTH SERVER:                      ||                             |
   |    | a. Validate refresh token         ||                             |
   |    |    - Exists in store?             ||                             |
   |    |    - Not expired?                 ||                             |
   |    |    - Not revoked?                 ||                             |
   |    | b. Generate NEW access token      ||                             |
   |    | c. (Optional) Rotate refresh      ||                             |
   |    |    token and invalidate old one   ||                             |
   |    +----------------------------------+|                             |
   |                                        |                             |
   | 8. 200 OK                             |                             |
   |    {                                   |                             |
   |      "access_token": "eyJhbG..NEW",  |                             |
   |      "refresh_token": "bmV3IHJ..NEW",|                             |
   |      "expires_in": 900                |                             |
   |    }                                   |                             |
   | <------------------------------------- |                             |
   |                                        |                             |
   | 9. RETRY: GET /api/data               |                             |
   |    Authorization: Bearer eyJhbG..NEW  |                             |
   | ----------------------------------------------------------->        |
   |                                        |                             |
   | 10. 200 OK { "data": [...] }          |                             |
   | <-----------------------------------------------------------        |
```

---

## Token Lifecycle

```
  TIME ──────────────────────────────────────────────────────────────>

  Access Token #1           Access Token #2           Access Token #3
  ├──────────────┤          ├──────────────┤          ├──────────────┤
  | 15 min       |          | 15 min       |          | 15 min       |
  | valid        | REFRESH  | valid        | REFRESH  | valid        |
  ├──────────────┤ -------> ├──────────────┤ -------> ├──────────────┤
                  ^                          ^
                  |                          |
             Token expires             Token expires
             Client uses              Client uses
             refresh token            refresh token

  Refresh Token
  ├────────────────────────────────────────────────────────────────────┤
  |                        30 days valid                                |
  |  (or until revoked by user, admin, or security event)              |
  ├────────────────────────────────────────────────────────────────────┤

  With Refresh Token Rotation:

  Refresh Token #1         Refresh Token #2         Refresh Token #3
  ├──────────────┤         ├──────────────┤         ├──────────────┤
  |  Used once   |ROTATED  |  Used once   |ROTATED  |  Used once   |
  |  then        | ------> |  then        | ------> |  then        |
  |  invalidated |         |  invalidated |         |  invalidated |
  ├──────────────┤         ├──────────────┤         ├──────────────┤
```

---

## Refresh Token Rotation

Refresh token rotation is a critical security mechanism where the auth server issues a **new refresh token** each time the old one is used, and immediately invalidates the old one.

```
  WITHOUT ROTATION (Dangerous):

  Attacker steals    Attacker uses     Attacker has
  refresh token      it to get         indefinite access
  ───────────────>   access tokens     ──────────────>
                     ───────────────>

  WITH ROTATION (Detectable):

  Attacker steals    Attacker uses       Auth server
  refresh token #3   stolen token #3     detects #3 was
  ───────────────>   to get new tokens   already used
                     ───────────────>    ──────────────>

                     Meanwhile, real                        Auth server
                     user tries to       ┌──────────────┐  REVOKES ALL
                     use token #3  ----> │ REUSE         │  tokens for
                                         │ DETECTED!     │  this family
                                         └──────────────┘  ──────────>

  TOKEN FAMILY CONCEPT:
  +-------------------------------------------------------------------+
  | All refresh tokens issued from a single authentication event      |
  | belong to a "family." If any token in the family is reused        |
  | (indicating theft), ALL tokens in the family are revoked.         |
  +-------------------------------------------------------------------+
```

---

## Comparison: Access Token vs. Refresh Token

| Feature | Access Token | Refresh Token |
|---------|-------------|---------------|
| **Purpose** | Access protected resources | Obtain new access tokens |
| **Lifetime** | Short (5-60 minutes) | Long (days to months) |
| **Sent to** | Resource server (API) | Auth server only |
| **Format** | Often JWT (self-contained) | Often opaque (random string) |
| **Storage (Browser)** | In-memory JavaScript variable | HTTP-only, Secure, SameSite cookie |
| **Storage (Mobile)** | In-memory | Keychain (iOS) / EncryptedSharedPreferences (Android) |
| **Revocation** | Difficult (if JWT) | Easy (delete from server store) |
| **Scope** | Contains scopes/permissions | No scopes -- just re-issues access tokens |
| **Network exposure** | Every API request | Only during token refresh |
| **If stolen** | Limited damage (expires soon) | Significant damage (long-lived) |

---

## Pros and Cons

| Pros | Cons |
|------|------|
| Short-lived access tokens limit compromise window | Added complexity (two tokens, refresh logic) |
| Users stay logged in without re-entering credentials | Client must handle token refresh gracefully |
| Refresh tokens can be revoked instantly | Refresh token theft is still dangerous |
| Supports per-device session management | Race conditions possible with concurrent refresh requests |
| Works well in distributed architectures | Requires server-side storage for refresh tokens |
| Refresh rotation detects token theft | Clock skew can cause premature expiration errors |

---

## Real-World Use Cases

- **Web applications** -- SPAs (React, Angular, Vue) use this pattern to maintain sessions without server-side state.
- **Mobile applications** -- iOS and Android apps use refresh tokens in secure storage for persistent login.
- **OAuth 2.0 implementations** -- Google, Microsoft, GitHub, and all major OAuth providers issue both token types.
- **Microservice architectures** -- Gateway services handle token refresh while backend services validate access tokens.
- **Banking applications** -- Short-lived access tokens (2-5 minutes) with refresh tokens that require step-up authentication.

---

## When to Use

- You need long user sessions (days/weeks) without compromising security.
- You are building an SPA, mobile app, or any client that makes frequent API calls.
- You want the ability to revoke sessions per device.
- You are implementing OAuth 2.0.
- You need to balance security (short-lived credentials) with UX (no constant re-login).

## When NOT to Use

- Server-rendered web applications where session cookies handle everything.
- Short-lived interactions (user logs in, performs one action, leaves).
- Machine-to-machine (M2M) communication where the client credentials grant is simpler (no user involvement, just re-authenticate).
- Very simple APIs where a single long-lived API key suffices.

---

## Security Considerations

### 1. Secure Refresh Token Storage

This is the most critical security consideration. A compromised refresh token grants long-term access.

```
  BROWSER:
  +----------------------------------------------+
  | Access Token:  JavaScript variable (in-memory)|
  |   - Cleared on page refresh (acceptable)      |
  |   - Not accessible via XSS in other tabs      |
  |                                                |
  | Refresh Token: HTTP-only Secure SameSite cookie|
  |   - Not accessible via JavaScript              |
  |   - Not sent cross-origin (SameSite=Strict)    |
  |   - Only sent over HTTPS (Secure flag)         |
  +----------------------------------------------+

  MOBILE:
  +----------------------------------------------+
  | iOS:     Keychain Services                     |
  | Android: EncryptedSharedPreferences            |
  |          or Android Keystore                   |
  +----------------------------------------------+

  SERVER:
  +----------------------------------------------+
  | Environment variables or secret managers       |
  | (HashiCorp Vault, AWS Secrets Manager)         |
  +----------------------------------------------+
```

### 2. Implement Refresh Token Rotation
Always rotate refresh tokens. Issue a new one each time the old one is used. This allows detection of token theft.

### 3. Bind Refresh Tokens to Devices
Associate each refresh token with device fingerprint metadata (IP address, User-Agent, device ID). Reject refresh requests from unexpected devices.

### 4. Rate Limit the Refresh Endpoint
Prevent brute-force attacks on the refresh endpoint. A legitimate client refreshes once every few minutes, not hundreds of times per second.

### 5. Implement Absolute Expiration
Even with rotation, set an absolute maximum lifetime for refresh tokens (e.g., 30 or 90 days). After that, the user must re-authenticate.

### 6. Handle Concurrent Refresh Requests
In SPAs, multiple API calls might fail simultaneously due to an expired access token, triggering multiple refresh requests. Implement a token refresh queue:

```
  WITHOUT QUEUE (Race Condition):
  Tab 1: API call fails -> Refresh request -> Gets new tokens
  Tab 2: API call fails -> Refresh request -> FAILS (old refresh token already used)

  WITH QUEUE (Correct):
  Tab 1: API call fails -> Enqueue refresh -> [Refresh executes] -> Retry with new token
  Tab 2: API call fails -> Enqueue refresh -> [Waits for Tab 1]  -> Retry with new token
```

### 7. Revocation Scenarios
Revoke all refresh tokens when:
- User changes password.
- User explicitly logs out.
- Admin disables the user account.
- Suspicious activity is detected.
- User revokes access from a specific device.

---

## Implementation Pattern: Silent Refresh for SPAs

```
  MAIN APPLICATION                     HIDDEN IFRAME
       |                                     |
       | Access token expires                |
       |                                     |
       | 1. Create hidden iframe             |
       | ----------------------------------> |
       |                                     |
       |    2. iframe loads:                 |
       |    /authorize?prompt=none           |
       |    (uses existing session cookie)   |
       |                                     |
       |    3. Auth server returns new       |
       |    tokens via redirect              |
       |                                     |
       | 4. iframe posts message to parent   |
       | <---------------------------------- |
       |                                     |
       | 5. Application stores new tokens    |
       | 6. Retries failed request           |

  NOTE: This pattern is being replaced by
  refresh token rotation with backend-for-frontend
  (BFF) pattern due to third-party cookie restrictions.
```

---

## Backend-for-Frontend (BFF) Pattern

The modern recommended approach for browser-based applications:

```
  BROWSER                    BFF (Backend)              AUTH SERVER       API
     |                           |                          |              |
     | 1. Login request          |                          |              |
     | ------------------------> |                          |              |
     |                           | 2. OAuth flow            |              |
     |                           | -----------------------> |              |
     |                           |                          |              |
     |                           | 3. Receive tokens        |              |
     |                           | <----------------------- |              |
     |                           |                          |              |
     |                           | [Store BOTH tokens       |              |
     |                           |  server-side]            |              |
     |                           |                          |              |
     | 4. Set session cookie     |                          |              |
     |    (HTTP-only, Secure,    |                          |              |
     |     SameSite=Strict)      |                          |              |
     | <------------------------ |                          |              |
     |                           |                          |              |
     | 5. API request            |                          |              |
     |    (with session cookie)  |                          |              |
     | ------------------------> |                          |              |
     |                           | 6. Look up access token  |              |
     |                           |    from session store     |              |
     |                           |                          |              |
     |                           | 7. Forward request        |              |
     |                           |    Authorization: Bearer  |              |
     |                           | ---------------------------------------->|
     |                           |                          |              |
     |                           | 8. Response              |              |
     |                           | <----------------------------------------|
     |                           |                          |              |
     | 9. Forward response       |                          |              |
     | <------------------------ |                          |              |

  ADVANTAGE: No tokens in the browser at all.
  The browser only has a session cookie.
```

---

## Recommended Token Lifetimes

| Application Type | Access Token | Refresh Token | Notes |
|-----------------|-------------|---------------|-------|
| Banking / Finance | 2-5 minutes | 15-30 minutes | Step-up auth for sensitive operations |
| Standard Web App | 15-30 minutes | 7-30 days | With refresh rotation |
| Mobile App | 30-60 minutes | 30-90 days | Longer due to secure native storage |
| Internal Tools | 1-8 hours | 30 days | Lower risk, higher convenience |
| M2M / Service | 1 hour | N/A | Use client credentials re-auth instead |

---

## Summary

The access/refresh token pattern is the foundation of secure, user-friendly authentication in modern applications. By separating the short-lived credential (access token) from the long-lived credential (refresh token), you minimize the damage from token theft while keeping users logged in for extended periods. Always implement refresh token rotation, store tokens securely (never in `localStorage`), and revoke all tokens on security-sensitive events like password changes. For browser-based applications, the Backend-for-Frontend (BFF) pattern provides the strongest security by keeping tokens entirely server-side.

---

*Previous: [JSON Web Tokens (JWT)](./05-jwt.md) | Next: [Single Sign-On (SSO)](./07-sso.md)*
