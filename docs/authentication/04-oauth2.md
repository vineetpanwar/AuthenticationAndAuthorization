# OAuth 2.0

## Introduction

OAuth 2.0 is the industry-standard **authorization framework** defined in **RFC 6749**. It enables third-party applications to obtain limited access to a user's resources on another service -- without the user sharing their password with the third-party application.

The classic example: you click "Sign in with Google" on a website. That website never sees your Google password. Instead, Google authenticates you directly and issues a token that grants the website specific, limited access (like reading your profile name and email).

OAuth 2.0 is **not an authentication protocol** by itself -- it is an authorization framework. Authentication is handled by extensions like **OpenID Connect (OIDC)**, which adds an identity layer on top of OAuth 2.0. However, OAuth 2.0 is so foundational that understanding it is essential for any modern authentication system.

---

## Key Terminology

| Term | Description |
|------|-------------|
| **Resource Owner** | The user who owns the data and grants access |
| **Client** | The application requesting access to the user's resources |
| **Authorization Server** | The server that authenticates the user and issues tokens (e.g., Google, Auth0, Okta) |
| **Resource Server** | The API server that hosts the protected resources |
| **Access Token** | A credential used to access protected resources |
| **Refresh Token** | A credential used to obtain new access tokens without re-authentication |
| **Scope** | A permission that limits what the access token can do (e.g., `read:email`, `write:repos`) |
| **Grant Type** | The method by which the client obtains an access token |
| **Redirect URI** | The URL where the authorization server sends the user after granting/denying access |

---

## The Four Grant Types

OAuth 2.0 defines four primary grant types (flows), each designed for different use cases:

| Grant Type | Best For | Involves User? |
|-----------|----------|----------------|
| **Authorization Code** | Web apps with a backend server | Yes |
| **Authorization Code + PKCE** | SPAs, mobile apps, native apps | Yes |
| **Client Credentials** | Server-to-server (machine-to-machine) | No |
| **Device Code** | TVs, CLI tools, IoT devices (no browser) | Yes |

> **Note:** The Implicit Grant and Resource Owner Password Credentials (ROPC) grant were part of the original OAuth 2.0 spec but are now **deprecated** in OAuth 2.1. Do not use them for new applications.

---

## Grant Type 1: Authorization Code Flow

This is the most common and most secure flow for web applications with a server-side backend.

### Step-by-Step

1. User clicks "Login with Provider" on the client application.
2. Client redirects the user's browser to the authorization server with required parameters.
3. User authenticates with the authorization server (enters username/password).
4. User reviews and consents to the requested scopes.
5. Authorization server redirects back to the client with an **authorization code**.
6. Client exchanges the authorization code for an **access token** (server-to-server call).
7. Client uses the access token to call the resource server.

### Flow Diagram

```
 USER          CLIENT (Browser)       CLIENT (Server)        AUTH SERVER          RESOURCE SERVER
  |                  |                      |                     |                      |
  | 1. Click         |                      |                     |                      |
  |    "Login"       |                      |                     |                      |
  | ---------------> |                      |                     |                      |
  |                  |                      |                     |                      |
  |  2. 302 Redirect to Auth Server        |                     |                      |
  |     /authorize?                         |                     |                      |
  |       response_type=code               |                     |                      |
  |       &client_id=abc123                |                     |                      |
  |       &redirect_uri=https://app/cb     |                     |                      |
  |       &scope=profile email             |                     |                      |
  |       &state=xyz789                    |                     |                      |
  | <----------------|                      |                     |                      |
  |                  |                      |                     |                      |
  |  3. User authenticates with Auth Server                      |                      |
  | -----------------------------------------------------------> |                      |
  |                  |                      |                     |                      |
  |  4. Consent screen: "Allow App to access your profile?"      |                      |
  | <----------------------------------------------------------- |                      |
  |                  |                      |                     |                      |
  |  5. User approves                      |                     |                      |
  | -----------------------------------------------------------> |                      |
  |                  |                      |                     |                      |
  |  6. 302 Redirect back to Client        |                     |                      |
  |     /callback?code=AUTH_CODE&state=xyz789                    |                      |
  | <----------------------------------------------------------- |                      |
  | ---------------> |                      |                     |                      |
  |                  | -------------------> |                     |                      |
  |                  |                      |                     |                      |
  |                  |   7. POST /oauth/token                    |                      |
  |                  |      grant_type=authorization_code         |                      |
  |                  |      code=AUTH_CODE                        |                      |
  |                  |      client_id=abc123                      |                      |
  |                  |      client_secret=SECRET                  |                      |
  |                  |      redirect_uri=https://app/cb           |                      |
  |                  |                      | ------------------> |                      |
  |                  |                      |                     |                      |
  |                  |   8. Token Response  |                     |                      |
  |                  |      {               |                     |                      |
  |                  |       access_token,  |                     |                      |
  |                  |       refresh_token, |                     |                      |
  |                  |       expires_in     |                     |                      |
  |                  |      }               |                     |                      |
  |                  |                      | <------------------ |                      |
  |                  |                      |                     |                      |
  |                  |   9. GET /api/profile                     |                      |
  |                  |      Authorization: Bearer <access_token>  |                      |
  |                  |                      | ------------------------------------------> |
  |                  |                      |                     |                      |
  |                  |  10. 200 OK          |                     |                      |
  |                  |      { name, email } |                     |                      |
  |                  |                      | <------------------------------------------ |
  |                  |                      |                     |                      |
  |  11. Display user profile              |                     |                      |
  | <----------------|                      |                     |                      |
```

---

## Grant Type 2: Authorization Code + PKCE

PKCE (Proof Key for Code Exchange, pronounced "pixy") was originally designed for mobile/native apps but is now **recommended for all OAuth clients**, including server-side apps.

PKCE prevents authorization code interception attacks by adding a one-time cryptographic challenge.

```
  CLIENT                                      AUTH SERVER
    |                                              |
    |  1. Generate:                                |
    |     code_verifier = random(43-128 chars)     |
    |     code_challenge = SHA256(code_verifier)   |
    |                                              |
    |  2. GET /authorize                           |
    |     ?response_type=code                      |
    |     &client_id=abc123                        |
    |     &code_challenge=E9Melhoa2OwvFrEMTJg...   |
    |     &code_challenge_method=S256              |
    |  ------------------------------------------> |
    |                                              |
    |  [User authenticates and consents]           |
    |                                              |
    |  3. Redirect with code                       |
    |  <------------------------------------------ |
    |                                              |
    |  4. POST /oauth/token                        |
    |     grant_type=authorization_code             |
    |     code=AUTH_CODE                            |
    |     code_verifier=dBjftJeZ4CVP-mB92K27u...   |
    |  ------------------------------------------> |
    |                                              |
    |     +--------------------------------------+ |
    |     | Auth Server:                          | |
    |     | a. Compute SHA256(code_verifier)      | |
    |     | b. Compare with stored code_challenge | |
    |     | c. If match, issue tokens             | |
    |     +--------------------------------------+ |
    |                                              |
    |  5. Token Response                           |
    |     { access_token, refresh_token }          |
    |  <------------------------------------------ |

  WHY PKCE WORKS:
  +---------------------------------------------------------+
  | Even if an attacker intercepts the authorization code,  |
  | they cannot exchange it for tokens because they do not  |
  | have the code_verifier (which never left the client).   |
  +---------------------------------------------------------+
```

---

## Grant Type 3: Client Credentials

Used for machine-to-machine communication where no user is involved.

```
  CLIENT (Backend Service)                    AUTH SERVER
    |                                              |
    |  1. POST /oauth/token                        |
    |     grant_type=client_credentials             |
    |     client_id=service-abc                     |
    |     client_secret=SECRET                      |
    |     scope=read:data                           |
    |  ------------------------------------------> |
    |                                              |
    |     +--------------------------------------+ |
    |     | Auth Server:                          | |
    |     | a. Validate client_id + secret        | |
    |     | b. Check authorized scopes            | |
    |     | c. Issue access token                 | |
    |     +--------------------------------------+ |
    |                                              |
    |  2. Token Response                           |
    |     { access_token, expires_in }             |
    |     (No refresh token -- just re-authenticate)|
    |  <------------------------------------------ |
```

---

## Grant Type 4: Device Code

For devices with limited input capabilities (smart TVs, CLI tools, IoT).

```
  DEVICE               USER's PHONE/LAPTOP          AUTH SERVER
    |                         |                          |
    | 1. POST /device/code    |                          |
    |    client_id=tv-app     |                          |
    | ----------------------------------------------------->
    |                         |                          |
    | 2. Response:            |                          |
    |    device_code=ABCD     |                          |
    |    user_code=WXYZ-1234  |                          |
    |    verification_uri=    |                          |
    |     https://auth.co/    |                          |
    |     device              |                          |
    | <-----------------------------------------------------
    |                         |                          |
    | 3. Display to user:     |                          |
    |  "Go to auth.co/device  |                          |
    |   Enter: WXYZ-1234"     |                          |
    |                         |                          |
    |                         | 4. User visits URL and   |
    |                         |    enters code WXYZ-1234 |
    |                         | -----------------------> |
    |                         |                          |
    |                         | 5. User authenticates    |
    |                         |    and approves           |
    |                         | -----------------------> |
    |                         |                          |
    | 6. POST /oauth/token    |                          |
    |    (polling)            |                          |
    |    grant_type=          |                          |
    |     device_code         |                          |
    |    device_code=ABCD     |                          |
    | ----------------------------------------------------->
    |                         |                          |
    | 7. Token Response       |                          |
    |    { access_token }     |                          |
    | <-----------------------------------------------------
```

---

## Pros and Cons

| Pros | Cons |
|------|------|
| Users never share passwords with third-party apps | Complex to implement correctly |
| Granular permission control via scopes | Many moving parts (redirects, tokens, state management) |
| Tokens can be time-limited and revoked | Misconfiguration can lead to serious vulnerabilities |
| Industry standard supported by all major providers | Requires understanding multiple grant types |
| Supports delegation (act on behalf of user) | Redirect-based flows can be confusing for users |
| Extensible (OpenID Connect, DPoP, PAR, etc.) | Token management adds operational complexity |

---

## Real-World Use Cases

- **Social login** -- "Sign in with Google/GitHub/Facebook" on web and mobile apps.
- **Third-party API integrations** -- Slack apps accessing workspace data, GitHub Apps accessing repositories.
- **Microservice architectures** -- Service-to-service authentication using client credentials.
- **Smart TV and IoT** -- Netflix, Spotify on TVs using device code flow.
- **CLI tools** -- GitHub CLI (`gh`), cloud provider CLIs using device code or authorization code flow.
- **Banking and fintech** -- Open Banking APIs use OAuth 2.0 for delegated access to financial data.

---

## When to Use

- You are building a platform where third-party apps need access to user data.
- You need "Sign in with X" social login functionality.
- You need delegated authorization (app acts on behalf of a user).
- Your architecture requires machine-to-machine authentication.
- You need fine-grained, revocable, scoped access control.

## When NOT to Use

- Simple internal APIs where API keys or Basic Auth suffice.
- When you only need authentication (consider OpenID Connect, which is OAuth 2.0 + identity).
- Very simple applications with a single user type and no third-party integration.
- When the implementation complexity outweighs the security benefits.

---

## Security Considerations

### 1. Always Use PKCE
Even for server-side clients, PKCE adds protection against code interception and is required in OAuth 2.1.

### 2. Validate the `state` Parameter
The `state` parameter prevents CSRF attacks. Generate a cryptographically random value, store it in the user's session, and validate it when the callback is received.

### 3. Validate Redirect URIs Exactly
Register redirect URIs with the authorization server and validate them with **exact string matching** (not pattern matching). Open redirectors are a common OAuth vulnerability.

### 4. Keep Access Tokens Short-Lived
Use short-lived access tokens (5-60 minutes) and refresh tokens for long-lived sessions. This limits the blast radius of token theft.

### 5. Use the `nonce` Parameter (with OIDC)
When using OpenID Connect, include a `nonce` to prevent token replay attacks.

### 6. Secure Client Secrets
- Never embed client secrets in mobile or SPA applications.
- Use PKCE instead of client secrets for public clients.
- Rotate client secrets regularly.

### 7. Scope Minimization
Request only the scopes you actually need. Do not request `admin` scope if you only need `read:profile`.

---

## Comparison: OAuth 2.0 Grant Types

| Feature | Auth Code | Auth Code + PKCE | Client Credentials | Device Code |
|---------|-----------|-------------------|--------------------|-------------|
| User involvement | Yes | Yes | No | Yes |
| Client type | Confidential | Public or Confidential | Confidential | Public |
| Redirect required | Yes | Yes | No | No |
| Refresh token | Yes | Yes | Typically no | Yes |
| Best for | Web apps (server) | SPAs, mobile, native | Microservices | TVs, CLIs, IoT |
| Security level | High | High | High | Medium |
| PKCE required | Recommended | Yes | N/A | N/A |

---

## OAuth 2.0 vs. OAuth 2.1

OAuth 2.1 (draft) consolidates best practices and removes insecure patterns:

| Change | OAuth 2.0 | OAuth 2.1 |
|--------|-----------|-----------|
| Implicit grant | Allowed | **Removed** |
| ROPC grant | Allowed | **Removed** |
| PKCE | Optional | **Required** for all auth code flows |
| Redirect URI matching | Flexible | **Exact match required** |
| Refresh token rotation | Optional | **Recommended** |
| Bearer tokens in query strings | Allowed | **Prohibited** |

---

## Summary

OAuth 2.0 is the backbone of modern authorization on the web. It elegantly solves the problem of granting third-party applications limited access to user resources without exposing credentials. While it is more complex than simpler authentication methods, this complexity is warranted by the security guarantees it provides. Choose the right grant type for your use case, follow security best practices (PKCE, short-lived tokens, exact redirect URI matching), and consider OpenID Connect when you need authentication in addition to authorization.

---

*Previous: [API Key Authentication](./03-api-keys.md) | Next: [JSON Web Tokens (JWT)](./05-jwt.md)*
