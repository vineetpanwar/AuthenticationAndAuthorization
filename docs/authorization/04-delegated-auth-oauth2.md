# OAuth2 for Delegated Authorization

## Introduction

OAuth 2.0 is an **authorization framework** (not an authentication protocol) that enables
a third-party application to obtain **limited access** to a user's resources on another
service, without the user sharing their password. It is the industry standard for delegated
authorization, defined in RFC 6749 (2012) and extended by numerous subsequent RFCs.

The key insight behind OAuth2 is the concept of **delegated authorization**: rather than
giving a third-party app your password (which grants unlimited access), you grant it a
**scoped, time-limited token** that allows access only to the specific resources you approve.

Before OAuth, the common pattern was "password anti-pattern" -- you would give your Google
password to a third-party app so it could access your Gmail. This was catastrophic for
security: the app had full access, you could not revoke it without changing your password,
and a breach of the app exposed your Google credentials. OAuth solved all of these problems.

Today, every "Sign in with Google/GitHub/Facebook" button and every API integration between
SaaS products relies on OAuth2 under the hood.

---

## Core Terminology

| Term                    | Description                                                      |
|-------------------------|------------------------------------------------------------------|
| **Resource Owner**      | The user who owns the data (you)                                 |
| **Client**              | The third-party application requesting access                    |
| **Authorization Server**| The server that authenticates the user and issues tokens (e.g., Google's auth server) |
| **Resource Server**     | The server hosting the protected resources (e.g., Google Drive API) |
| **Access Token**        | A credential the client uses to access the resource server       |
| **Refresh Token**       | A long-lived token used to obtain new access tokens              |
| **Scope**               | A string defining the extent of access (e.g., `read:email`, `repo`) |
| **Grant Type**          | The method used to obtain an access token                        |
| **Redirect URI**        | The URL where the authorization server sends the user after consent |

---

## How It Works: Authorization Code Flow (Step by Step)

The Authorization Code flow is the most common and most secure OAuth2 flow for web
applications. Here is the step-by-step process:

1. **User Initiates** -- The user clicks "Connect with GitHub" in a third-party app (Client).

2. **Client Redirects** -- The Client redirects the user's browser to the Authorization
   Server with a request containing `client_id`, `redirect_uri`, `scope`, `state`, and
   `response_type=code`.

3. **User Authenticates** -- The Authorization Server presents a login screen (if needed)
   and a consent screen showing the requested scopes.

4. **User Consents** -- The user reviews and approves the requested permissions.

5. **Authorization Code Issued** -- The Authorization Server redirects the user back to the
   Client's `redirect_uri` with a short-lived **authorization code** and the `state` parameter.

6. **Client Exchanges Code** -- The Client's backend sends the authorization code, along
   with `client_id` and `client_secret`, directly to the Authorization Server's token endpoint
   (server-to-server, not through the browser).

7. **Tokens Issued** -- The Authorization Server validates the code and returns an
   **access token** (and optionally a **refresh token**).

8. **Client Accesses Resources** -- The Client uses the access token to make API calls to
   the Resource Server.

9. **Token Refresh** -- When the access token expires, the Client uses the refresh token
   to obtain a new access token without requiring user interaction.

---

## OAuth2 Authorization Code Flow (ASCII Diagram)

```
     +----------+                                +-------------------+
     |  User    |                                | Third-Party App   |
     | (Resource|                                | (Client)          |
     |  Owner)  |                                +--------+----------+
     +----+-----+                                         |
          |                                               |
          | (1) Click "Connect with GitHub"               |
          +---------------------------------------------->|
          |                                               |
          |  (2) Redirect to Authorization Server         |
          |<----------------------------------------------+
          |      GET /authorize?                          |
          |        response_type=code&                    |
          |        client_id=abc123&                      |
          |        redirect_uri=https://app.com/callback& |
          |        scope=repo+read:user&                  |
          |        state=xyz789                           |
          |                                               |
          v                                               |
     +----+-----------------+                             |
     | Authorization Server |                             |
     | (e.g., GitHub)       |                             |
     +----+-----------------+                             |
          |                                               |
          | (3) Show login + consent screen               |
          |     "App wants to access your repos           |
          |      and read your profile"                   |
          |                                               |
          | (4) User approves                             |
          |                                               |
          | (5) Redirect back with authorization code     |
          +---------------------------------------------->|
               302 Location: https://app.com/callback?    |
                 code=AUTH_CODE_HERE&                      |
                 state=xyz789                              |
                                                          |
                                              (6) Exchange code for token
                                              POST /oauth/token
                                                {                         +-------------------+
                                                  grant_type: "auth_code",| Authorization     |
                                                  code: AUTH_CODE_HERE,   | Server (GitHub)   |
                                                  client_id: abc123,      +--------+----------+
                                                  client_secret: SECRET   |        |
                                                }  ---------------------->|        |
                                                                          |        |
                                              (7) Receive tokens          |        |
                                              {                           |        |
                                                access_token: "eyJhb...",<---------+
                                                token_type: "bearer",     |
                                                expires_in: 3600,         |
                                                refresh_token: "dGhpcw.." |
                                              }                           |
                                                          |               |
                                              (8) Use access token        |
                                              GET /api/repos              |
                                              Authorization: Bearer eyJhb.|
                                                          +-------------->+-------------------+
                                                          |               | Resource Server   |
                                                          |<--------------| (GitHub API)      |
                                                          | 200 OK        +-------------------+
                                                          | [{repo data}]
```

---

## OAuth2 Grant Types

### 1. Authorization Code (with PKCE)

**Best for:** Web apps, mobile apps, single-page apps (SPAs)

This is the standard flow described above. **PKCE** (Proof Key for Code Exchange, RFC 7636)
adds protection against authorization code interception attacks and is now recommended
for ALL clients, not just public clients.

```
PKCE Addition:

  Client generates:
    code_verifier  = random_string(43-128 chars)
    code_challenge = BASE64URL(SHA256(code_verifier))

  Step 2: Include code_challenge in /authorize request
  Step 6: Include code_verifier in /token request
  Server: Verify SHA256(code_verifier) == code_challenge
```

### 2. Client Credentials

**Best for:** Service-to-service communication (no user involved)

```
  +------------------+                    +-------------------+
  | Service A        |  POST /token       | Authorization     |
  | (Client)         |  grant_type=       | Server            |
  |                  |  client_credentials|                   |
  |                  | ------------------>|                   |
  |                  |                    |                   |
  |                  |  access_token      |                   |
  |                  | <------------------|                   |
  +------------------+                    +-------------------+
```

### 3. Device Authorization (Device Code Flow)

**Best for:** Devices with limited input (smart TVs, CLI tools, IoT devices)

```
  +----------+        +------------------+        +-------------------+
  | Smart TV |        | User's Phone     |        | Auth Server       |
  +----+-----+        +--------+---------+        +---------+---------+
       |                       |                            |
       | (1) POST /device/code |                            |
       | --------------------------------------------->     |
       |                       |                            |
       | (2) Display:          |                            |
       | "Go to github.com/   |                            |
       |  device and enter     |                            |
       |  code: ABCD-1234"    |                            |
       |                       |                            |
       |                       | (3) User visits URL        |
       |                       |     and enters code        |
       |                       | -------------------------->|
       |                       |                            |
       |                       | (4) User authenticates     |
       |                       |     and consents           |
       |                       | <--------------------------|
       |                       |                            |
       | (5) Poll POST /token  |                            |
       |     (device_code)     |                            |
       | --------------------------------------------->     |
       |                       |                            |
       | (6) Receive tokens    |                            |
       | <---------------------------------------------|    |
       |                                                    |
```

### 4. Deprecated Flows

- **Implicit Flow** -- Returned tokens directly in the URL fragment. Deprecated due to
  token leakage risks. Use Authorization Code + PKCE instead.
- **Resource Owner Password Credentials (ROPC)** -- The client collects the user's username
  and password directly. Deprecated because it defeats the purpose of OAuth. Only acceptable
  for migrating legacy systems.

---

## Scopes: Limiting Access

Scopes are the mechanism by which OAuth2 implements the principle of least privilege.
Instead of granting full access, the client requests only the permissions it needs.

### Examples from Popular Platforms

**GitHub Scopes:**
```
repo                Full control of private repositories
repo:status         Access commit status
repo:invite         Access repository invitations
read:user           Read user profile data
user:email          Read user email addresses
read:org            Read org membership
write:packages      Upload packages to GitHub Packages
```

**Google Scopes:**
```
https://www.googleapis.com/auth/drive.readonly     Read-only Drive access
https://www.googleapis.com/auth/drive.file          Per-file access (only files opened/created by app)
https://www.googleapis.com/auth/calendar.events     Manage calendar events
https://www.googleapis.com/auth/gmail.send          Send email only (not read)
```

**Stripe Scopes (for Connect):**
```
read_write          Full access to the account
read_only           Read-only access to account data
```

### Scope Consent Screen

```
+----------------------------------------------------------+
|                                                          |
|  "ThirdPartyApp" wants to access your GitHub account     |
|                                                          |
|  This application will be able to:                       |
|                                                          |
|  [x] Read your profile information (read:user)           |
|  [x] Read your email addresses (user:email)              |
|  [x] Access your public and private repositories (repo)  |
|                                                          |
|  +------------------+    +-------------------+           |
|  |    Authorize     |    |      Cancel       |           |
|  +------------------+    +-------------------+           |
|                                                          |
+----------------------------------------------------------+
```

---

## Real-World Examples

### GitHub OAuth Apps and GitHub Apps

GitHub supports two OAuth integration models:

1. **OAuth Apps** -- Traditional OAuth2. The app requests scopes and gets a user token.
   Scopes are coarse-grained (e.g., `repo` grants access to ALL repositories).

2. **GitHub Apps** -- Installed per-organization or per-repo. Permissions are fine-grained
   and tied to specific repositories. Uses JWTs + installation tokens instead of user tokens.

### Slack Bot Tokens

When you add a Slack app to your workspace, OAuth2 runs in the background:
- The app requests scopes like `chat:write`, `channels:read`, `users:read`.
- The workspace admin consents on behalf of the organization.
- The app receives a bot token scoped to those permissions.

### Stripe Connect

Stripe uses OAuth2 for its Connect platform, where third-party apps can manage Stripe
accounts on behalf of merchants. The OAuth flow grants the platform limited access to the
merchant's Stripe account.

---

## Security Considerations

### Common Attacks and Mitigations

| Attack                         | Mitigation                                               |
|--------------------------------|----------------------------------------------------------|
| **Authorization Code Theft**   | Use PKCE. Verify `state` parameter to prevent CSRF.      |
| **Token Leakage (URL)**        | Never return tokens in URLs. Use Authorization Code flow. |
| **Redirect URI Manipulation**  | Exact-match `redirect_uri` validation. No wildcards.      |
| **Token Replay**               | Short-lived access tokens. Audience (`aud`) validation.   |
| **Refresh Token Theft**        | Rotate refresh tokens on each use. Bind to client.        |
| **Cross-Site Request Forgery** | Use `state` parameter (random, per-session).              |
| **Clickjacking**               | X-Frame-Options / CSP frame-ancestors on consent page.    |

### Token Lifetime Best Practices

```
  Access Token:   5 - 60 minutes (short-lived, limits damage if stolen)
  Refresh Token:  7 - 90 days (long-lived, stored securely server-side)
  Auth Code:      30 - 60 seconds (single-use, very short-lived)
```

### PKCE Flow Detail

```
  Client:
    code_verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code_challenge = BASE64URL(SHA256(code_verifier))
                   = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

  /authorize?...&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
                &code_challenge_method=S256

  /token: { ..., code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" }

  Server verifies: SHA256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
                    == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" ? YES -> issue token
```

---

## Pros and Cons

### Advantages

- **No Password Sharing** -- Users never give their credentials to third-party apps.
- **Scoped Access** -- Tokens carry only the permissions the user approved.
- **Revocable** -- Users can revoke an app's access at any time without changing their password.
- **Standard Protocol** -- Universally supported by identity providers and API platforms.
- **Separation of Concerns** -- Authentication is handled by the Authorization Server,
  not by each individual application.
- **Token-Based** -- Enables stateless, scalable resource servers.

### Disadvantages

- **Complexity** -- Multiple flows, token types, and security considerations make
  implementation non-trivial.
- **Not Authentication** -- OAuth2 alone does not tell the Client who the user is.
  That requires OpenID Connect (OIDC), which is a layer on top of OAuth2.
- **Scope Limitations** -- Scopes are often coarse (GitHub's `repo` grants access to ALL
  repos, not just specific ones).
- **Token Management** -- Clients must handle token storage, refresh, and revocation correctly.
- **Phishing Risk** -- Fake consent screens can trick users into authorizing malicious apps.
- **Specification Ambiguity** -- The OAuth2 spec is intentionally flexible, leading to
  inconsistent implementations across providers.

---

## When to Use OAuth2

**Use OAuth2 when:**

- You need to let third-party apps access user resources on your platform (API integrations).
- You are building a platform with a public API (you are the Authorization Server).
- You want to enable "Sign in with X" (use OAuth2 + OIDC).
- You need service-to-service authorization (Client Credentials flow).
- You want to integrate with existing identity providers (Google, GitHub, Okta, Auth0).

**Do not use OAuth2 when:**

- You only need simple authentication (consider OIDC directly, or API keys).
- You control both the client and the resource server and there is no delegation needed
  (internal microservices may use mTLS or JWTs directly).
- You need real-time revocation with zero latency (JWTs are not immediately revocable).

---

## Implementation Considerations

### Choosing a Library / Service

| Approach              | Examples                                                      |
|-----------------------|---------------------------------------------------------------|
| **Managed Service**   | Auth0, Okta, AWS Cognito, Firebase Auth, Clerk                |
| **Self-Hosted Server**| Keycloak, Ory Hydra, Authelia, Authentik                      |
| **Client Library**    | passport.js (Node), spring-security-oauth2 (Java),           |
|                       | authlib (Python), golang.org/x/oauth2 (Go)                   |

### Token Storage

```
  Server-Side Web App:
    - Store tokens in a server-side session (Redis, DB)
    - Never expose tokens to the browser

  Single-Page App (SPA):
    - Use "Backend for Frontend" (BFF) pattern
    - Store tokens in HttpOnly, Secure, SameSite cookies
    - Do NOT store tokens in localStorage (XSS risk)

  Mobile App:
    - Use platform secure storage (iOS Keychain, Android Keystore)
    - Always use PKCE
```

---

## Comparison with Other Authorization Models

| Dimension              | OAuth2 (Delegated)    | RBAC              | ABAC              | API Keys       |
|------------------------|-----------------------|-------------------|--------------------|----------------|
| Purpose                | Delegate access       | Internal authz    | Complex policies   | Simple auth    |
| Scoped access          | Yes (scopes)          | Yes (roles)       | Yes (attributes)   | No (all-or-nothing)|
| User consent           | Yes                   | No                | No                 | No             |
| Token-based            | Yes                   | Optional          | No                 | Yes            |
| Third-party access     | Primary use case      | Not designed for  | Not designed for   | Risky          |
| Revocable              | Yes (per-app)         | Yes (role removal)| Yes (policy change)| Yes (key rotation)|
| Standard               | RFC 6749              | NIST              | NIST SP 800-162    | None           |

---

## Key Takeaways

1. OAuth2 enables **delegated authorization** -- users grant third-party apps limited access
   to their resources without sharing passwords.
2. The **Authorization Code + PKCE** flow is the recommended flow for almost all use cases.
3. **Scopes** implement the principle of least privilege by limiting what a token can do.
4. OAuth2 is for **authorization**, not authentication. Use OpenID Connect (OIDC) for identity.
5. Security requires: PKCE, state parameter, exact redirect URI matching, short-lived tokens,
   and secure token storage.
6. Every major platform (Google, GitHub, Slack, Stripe) uses OAuth2 as the foundation for
   third-party integrations.

---

## Further Reading

- RFC 6749: The OAuth 2.0 Authorization Framework
- RFC 7636: Proof Key for Code Exchange (PKCE)
- RFC 9449: OAuth 2.0 Demonstrating Proof of Possession (DPoP)
- OAuth 2.1 Draft: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-07
- OAuth.net: https://oauth.net/2/
- Aaron Parecki, "OAuth 2.0 Simplified": https://www.oauth.com/
