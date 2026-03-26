# Single Sign-On (SSO) with SAML and OAuth2

## Introduction

Single Sign-On (SSO) is an authentication architecture that allows users to **log in once** and gain access to **multiple independent applications** without being prompted to authenticate again. When you log into Google and then seamlessly access Gmail, YouTube, Google Drive, and Google Calendar without entering your password again -- that is SSO in action.

SSO is a critical component of enterprise identity management. It improves user experience (one password to remember), strengthens security (centralized authentication policies), and reduces IT support costs (fewer password reset tickets).

The two dominant protocols for implementing SSO are:

- **SAML 2.0** (Security Assertion Markup Language) -- An XML-based, enterprise-focused protocol. Published in 2005. Dominant in enterprise and government systems.
- **OAuth 2.0 / OpenID Connect (OIDC)** -- A modern, JSON-based protocol stack. OIDC (2014) adds an identity layer on top of OAuth 2.0. Dominant in consumer and modern enterprise applications.

---

## Key Terminology

| Term | Description |
|------|-------------|
| **Identity Provider (IdP)** | The system that authenticates users and asserts their identity (e.g., Okta, Azure AD, Google, OneLogin) |
| **Service Provider (SP)** | The application that the user wants to access (also called "Relying Party" in OIDC) |
| **Assertion** | A statement from the IdP about the user's identity and attributes (SAML term) |
| **ID Token** | A JWT containing identity claims (OIDC term, equivalent to a SAML assertion) |
| **Federation** | Trust relationship between an IdP and one or more SPs |
| **Session** | The authenticated state maintained by the IdP across applications |
| **SP-Initiated SSO** | User starts at the application, gets redirected to the IdP |
| **IdP-Initiated SSO** | User starts at the IdP portal and selects an application |

---

## How SSO Works (High-Level Concept)

```
  WITHOUT SSO:                          WITH SSO:
  +-------------------+                 +-------------------+
  |                   |                 |                   |
  | App A: Login      |                 | Identity Provider |
  | App B: Login      |                 |   (Login ONCE)    |
  | App C: Login      |                 |        |          |
  |                   |                 |    +---+---+      |
  | 3 passwords       |                 |    |   |   |      |
  | 3 sessions        |                 |  App A B   C      |
  | 3 login forms     |                 |  (all accessible) |
  +-------------------+                 +-------------------+


  SSO Session Flow:

  USER          APP A (SP)        IDENTITY PROVIDER         APP B (SP)
    |               |                     |                      |
    | 1. Visit App A|                     |                      |
    | ------------> |                     |                      |
    |               |                     |                      |
    |  2. Redirect to IdP                 |                      |
    | <------------ |                     |                      |
    | ----------------------------------> |                      |
    |               |                     |                      |
    |  3. Login (username + password)     |                      |
    | ----------------------------------> |                      |
    |               |                     |                      |
    |  4. IdP creates SESSION             |                      |
    |     and redirects to App A          |                      |
    |     with identity assertion         |                      |
    | <---------------------------------- |                      |
    | ------------> |                     |                      |
    |               |                     |                      |
    |  5. App A grants access             |                      |
    | <------------ |                     |                      |
    |               |                     |                      |
    |  ~~~~~~~~~~~~ TIME PASSES ~~~~~~~~  |                      |
    |               |                     |                      |
    |  6. Visit App B                     |                      |
    | ---------------------------------------------------------->
    |               |                     |                      |
    |  7. Redirect to IdP                 |                      |
    | <----------------------------------------------------------
    | ----------------------------------> |                      |
    |               |                     |                      |
    |  8. IdP detects EXISTING SESSION    |                      |
    |     NO login required!              |                      |
    |     Redirects to App B with         |                      |
    |     identity assertion              |                      |
    | <---------------------------------- |                      |
    | ---------------------------------------------------------->
    |               |                     |                      |
    |  9. App B grants access (no login!) |                      |
    | <----------------------------------------------------------
```

---

## SAML 2.0 (Security Assertion Markup Language)

### Overview

SAML 2.0 is an XML-based open standard for exchanging authentication and authorization data between an Identity Provider (IdP) and a Service Provider (SP). It has been the backbone of enterprise SSO since 2005.

### SAML Components

```
  +-------------------+        +---------------------+       +------------------+
  |   SAML ASSERTION  |        |   SAML PROTOCOL     |       |   SAML BINDING   |
  |                   |        |                     |       |                  |
  | The XML document  |        | Request/Response    |       | How messages are |
  | containing:       |        | messages:           |       | transported:     |
  | - Authentication  |        | - AuthnRequest      |       | - HTTP Redirect  |
  |   statement       |        | - Response          |       | - HTTP POST      |
  | - Attribute       |        | - LogoutRequest     |       | - HTTP Artifact  |
  |   statement       |        | - LogoutResponse    |       | - SOAP           |
  | - Authorization   |        |                     |       |                  |
  |   decision        |        |                     |       |                  |
  +-------------------+        +---------------------+       +------------------+
```

### SP-Initiated SAML Flow (Most Common)

```
 USER            SERVICE PROVIDER (SP)          IDENTITY PROVIDER (IdP)
   |                     |                              |
   | 1. GET /app/dashboard                              |
   | ------------------> |                              |
   |                     |                              |
   |                     | [User not authenticated]     |
   |                     | [Generate AuthnRequest]      |
   |                     |                              |
   | 2. 302 Redirect     |                              |
   |    Location: https://idp.example.com/sso?          |
   |      SAMLRequest=<base64-encoded-xml>              |
   |      &RelayState=/app/dashboard                    |
   | <------------------ |                              |
   |                     |                              |
   | 3. Browser follows redirect to IdP                 |
   | -------------------------------------------------> |
   |                     |                              |
   |                     |    +------------------------+|
   |                     |    | IdP checks for         ||
   |                     |    | existing session:       ||
   |                     |    |                        ||
   |                     |    | NO SESSION:            ||
   |                     |    |  -> Show login form    ||
   |                     |    |                        ||
   |                     |    | HAS SESSION:           ||
   |                     |    |  -> Skip to step 6     ||
   |                     |    +------------------------+|
   |                     |                              |
   | 4. Login form displayed                            |
   | <------------------------------------------------- |
   |                     |                              |
   | 5. POST credentials (username + password)          |
   | -------------------------------------------------> |
   |                     |                              |
   |                     |    +------------------------+|
   |                     |    | IdP:                    ||
   |                     |    | a. Validate credentials ||
   |                     |    | b. Create SSO session   ||
   |                     |    | c. Build SAML Response  ||
   |                     |    |    containing:          ||
   |                     |    |    - Assertion           ||
   |                     |    |    - NameID (user ID)   ||
   |                     |    |    - Attributes          ||
   |                     |    |    - Conditions          ||
   |                     |    |    - Signature           ||
   |                     |    | d. Sign with IdP        ||
   |                     |    |    private key           ||
   |                     |    +------------------------+|
   |                     |                              |
   | 6. Auto-submit form (HTTP POST Binding)            |
   |    <form action="https://sp.example.com/acs"       |
   |          method="POST">                            |
   |      <input name="SAMLResponse"                    |
   |             value="<base64-encoded-xml>"/>          |
   |      <input name="RelayState"                      |
   |             value="/app/dashboard"/>                |
   |    </form>                                         |
   | <------------------------------------------------- |
   |                     |                              |
   | 7. Browser POSTs SAML Response to SP               |
   | ------------------> |                              |
   |                     |                              |
   |                     | +---------------------------+|
   |                     | | SP (Assertion Consumer     ||
   |                     | |     Service - ACS):        ||
   |                     | |                           ||
   |                     | | a. Parse SAML Response    ||
   |                     | | b. Validate XML signature ||
   |                     | |    using IdP public cert  ||
   |                     | | c. Check conditions:      ||
   |                     | |    - NotBefore/NotOnOrAfter||
   |                     | |    - Audience restriction  ||
   |                     | |    - InResponseTo matches  ||
   |                     | | d. Extract NameID and     ||
   |                     | |    attributes              ||
   |                     | | e. Create local session   ||
   |                     | +---------------------------+|
   |                     |                              |
   | 8. 302 Redirect to RelayState (/app/dashboard)    |
   |    Set-Cookie: session=abc123                      |
   | <------------------ |                              |
   |                     |                              |
   | 9. Dashboard loads (authenticated!)                |
   | ------------------> |                              |
   | <------------------ |                              |
```

---

## OAuth 2.0 / OpenID Connect SSO

### Overview

OpenID Connect (OIDC) builds an identity layer on top of OAuth 2.0, providing a standardized way to authenticate users and obtain their profile information. It uses JSON instead of XML, JWTs instead of SAML assertions, and REST endpoints instead of SOAP-style bindings.

### OIDC SSO Flow

```
 USER            RELYING PARTY (App)         OPENID PROVIDER (IdP)
   |                     |                              |
   | 1. Click "Login"    |                              |
   | ------------------> |                              |
   |                     |                              |
   |                     | [Generate state + nonce]     |
   |                     | [Generate PKCE verifier]     |
   |                     |                              |
   | 2. 302 Redirect to OIDC Provider                   |
   |    Location: https://idp.example.com/authorize?    |
   |      response_type=code                            |
   |      &client_id=app-123                            |
   |      &redirect_uri=https://app.com/callback        |
   |      &scope=openid profile email                   |
   |      &state=random-csrf-token                      |
   |      &nonce=random-replay-token                    |
   |      &code_challenge=SHA256(verifier)              |
   |      &code_challenge_method=S256                   |
   | <------------------ |                              |
   |                     |                              |
   | 3. Browser redirects to IdP                        |
   | -------------------------------------------------> |
   |                     |                              |
   |    [IdP checks for existing session]               |
   |    [If no session: show login form]                |
   |    [If session exists: skip login]                 |
   |                     |                              |
   | 4. User authenticates (if needed)                  |
   | -------------------------------------------------> |
   |                     |                              |
   | 5. 302 Redirect back to app                        |
   |    Location: https://app.com/callback?             |
   |      code=AUTH_CODE                                |
   |      &state=random-csrf-token                      |
   | <------------------------------------------------- |
   | ------------------> |                              |
   |                     |                              |
   |                     | 6. POST /oauth/token         |
   |                     |    grant_type=authorization_code
   |                     |    code=AUTH_CODE             |
   |                     |    code_verifier=PKCE_VERIFIER
   |                     |    client_id=app-123         |
   |                     |    client_secret=SECRET      |
   |                     | ---------------------------> |
   |                     |                              |
   |                     | 7. Token Response:           |
   |                     |    {                         |
   |                     |      "access_token": "...",  |
   |                     |      "id_token": "eyJ...",   |
   |                     |      "refresh_token": "..."  |
   |                     |    }                         |
   |                     | <--------------------------- |
   |                     |                              |
   |                     | [Validate id_token JWT:      |
   |                     |  - Verify signature          |
   |                     |  - Check iss, aud, exp       |
   |                     |  - Check nonce matches       |
   |                     |  - Extract user identity]    |
   |                     |                              |
   |                     | 8. GET /userinfo (optional)  |
   |                     |    Authorization: Bearer ... |
   |                     | ---------------------------> |
   |                     |                              |
   |                     | 9. { "sub": "user-123",     |
   |                     |      "name": "John Doe",    |
   |                     |      "email": "john@..." }  |
   |                     | <--------------------------- |
   |                     |                              |
   | 10. Create session + redirect to app               |
   |     Set-Cookie: session=xyz789                     |
   | <------------------ |                              |
```

---

## SAML vs. OpenID Connect: Detailed Comparison

| Feature | SAML 2.0 | OpenID Connect (OIDC) |
|---------|---------|----------------------|
| **Year introduced** | 2005 | 2014 |
| **Data format** | XML | JSON |
| **Token format** | XML Assertion | JWT (ID Token) |
| **Transport** | HTTP Redirect, HTTP POST, SOAP | HTTP REST (JSON over HTTPS) |
| **Signing** | XML Digital Signature (XML-DSig) | JWS (JSON Web Signature) |
| **Encryption** | XML Encryption | JWE (JSON Web Encryption) |
| **Discovery** | Metadata XML document | `.well-known/openid-configuration` |
| **Complexity** | High | Moderate |
| **Token size** | Large (XML verbose) | Compact (JSON/JWT) |
| **Mobile friendly** | Poor (XML parsing on mobile is painful) | Excellent (native JSON support) |
| **SPA friendly** | Poor | Excellent |
| **Enterprise adoption** | Very high (legacy systems) | Growing rapidly |
| **Consumer adoption** | Low | Dominant ("Login with Google/GitHub") |
| **IdP-Initiated flow** | Supported natively | Not standard (workarounds exist) |
| **Single Logout (SLO)** | Supported (complex) | Supported (simpler) |
| **Library ecosystem** | Mature but aging | Modern and actively maintained |
| **Standard body** | OASIS | OpenID Foundation |

---

## Single Logout (SLO)

```
  SAML Single Logout:

  USER         APP A (SP)        IDENTITY PROVIDER        APP B (SP)
    |               |                    |                      |
    | 1. Logout     |                    |                      |
    |   from App A  |                    |                      |
    | ------------> |                    |                      |
    |               |                    |                      |
    |               | 2. LogoutRequest   |                      |
    |               |    (signed XML)    |                      |
    |               | -----------------> |                      |
    |               |                    |                      |
    |               |                    | 3. LogoutRequest     |
    |               |                    |    to App B          |
    |               |                    | -------------------> |
    |               |                    |                      |
    |               |                    | 4. LogoutResponse    |
    |               |                    |    (session cleared) |
    |               |                    | <------------------- |
    |               |                    |                      |
    |               |                    | [Destroy IdP session]|
    |               |                    |                      |
    |               | 5. LogoutResponse  |                      |
    |               | <----------------- |                      |
    |               |                    |                      |
    | 6. Logged out |                    |                      |
    |    from ALL   |                    |                      |
    |    applications                    |                      |
    | <------------ |                    |                      |


  OIDC Logout Approaches:

  1. RP-Initiated Logout:
     Redirect to: https://idp.example.com/logout?
       id_token_hint=<id_token>&
       post_logout_redirect_uri=https://app.com/logged-out

  2. Back-Channel Logout (Server-to-Server):
     IdP POSTs a Logout Token (JWT) to each RP's back-channel endpoint.

  3. Front-Channel Logout (Browser-Based):
     IdP renders hidden iframes pointing to each RP's logout endpoint.
```

---

## Pros and Cons of SSO

| Pros | Cons |
|------|------|
| One set of credentials for all applications | Single point of failure (IdP goes down = no login anywhere) |
| Improved user experience (no re-login) | Compromised IdP account = access to ALL applications |
| Centralized security policies (MFA, password complexity) | Complex to implement and maintain |
| Reduced password fatigue | Requires trust relationship setup between IdP and every SP |
| Easier onboarding/offboarding (disable IdP account = disable all access) | Single Logout is notoriously difficult to implement correctly |
| Better audit trails (centralized login logs) | Vendor lock-in risk with proprietary IdP features |
| Reduced IT support costs (fewer password resets) | Latency added by redirects to IdP |

---

## Real-World Use Cases

- **Enterprise environments** -- Employees use Okta/Azure AD to access Salesforce, Slack, Jira, Confluence, AWS Console, and hundreds of other SaaS applications.
- **Education** -- Students authenticate once through their university's IdP to access the LMS, email, library systems, and research tools.
- **Government** -- Federal agencies use PIV/CAC card authentication through a central IdP for all government applications.
- **Consumer platforms** -- Google SSO across Gmail, YouTube, Drive, Maps, and third-party "Login with Google" integrations.
- **Healthcare** -- Clinicians authenticate once to access EHR systems, imaging tools, and lab systems (with HIPAA-compliant IdPs).
- **SaaS platforms** -- Enterprise customers demand SSO integration (SAML or OIDC) before purchasing.

---

## When to Use SAML

- Integrating with existing enterprise IdPs (many only support SAML).
- Government or regulated industries with established SAML infrastructure.
- Applications that require IdP-initiated SSO.
- When your customers explicitly require SAML support.

## When to Use OIDC

- New applications (greenfield development).
- Mobile or SPA applications.
- Consumer-facing "Login with X" functionality.
- When you want simpler implementation and modern tooling.
- Microservice architectures where JWT validation is preferred.

## When to Use Both

Many enterprise applications support **both** SAML and OIDC to accommodate different customer requirements. Libraries like Passport.js (Node), Spring Security (Java), and OmniAuth (Ruby) make it feasible to support multiple protocols.

---

## Security Considerations

### 1. Protect the IdP
The IdP is the crown jewel. If it is compromised, all applications are compromised. Apply:
- Multi-factor authentication (MFA) for all users.
- Strong admin access controls.
- Regular security audits and penetration testing.
- Geo-fencing and anomaly detection.

### 2. Validate Assertions/Tokens Thoroughly
- **SAML:** Validate XML signatures, check `NotBefore`/`NotOnOrAfter`, verify `Audience`, check `InResponseTo`.
- **OIDC:** Validate JWT signature, check `iss`, `aud`, `exp`, `nonce`, and `at_hash`.

### 3. Prevent Replay Attacks
- SAML: Track consumed assertion IDs and reject duplicates within the validity window.
- OIDC: Use the `nonce` parameter and track consumed values.

### 4. Secure the Redirect/Callback URLs
- Register exact redirect URIs (no wildcards).
- Validate the `state` parameter to prevent CSRF.
- In SAML, validate the `Destination` attribute matches the ACS URL.

### 5. Implement Proper Session Management
- Set reasonable session timeouts at both the IdP and SP level.
- Implement Single Logout (even if imperfect, it is better than nothing).
- Provide users with a "sign out everywhere" option.

### 6. Certificate and Key Management (SAML)
- Rotate signing certificates before they expire.
- Distribute new certificates to all SPs ahead of rotation.
- Use 2048-bit RSA or ECDSA for signing.

### 7. Handle Account Linking
When a user from the IdP does not have an account in the SP:
- **Just-in-time provisioning (JIT):** Automatically create the account on first login.
- **SCIM provisioning:** Pre-provision accounts via the SCIM protocol.
- **Manual linking:** Require admin approval before granting access.

---

## Architecture Decision: SAML vs. OIDC

```
  START
    |
    v
  Is this a new application?
    |             |
   YES           NO
    |             |
    v             v
  Use OIDC     Do your enterprise customers require SAML?
                  |             |
                 YES           NO
                  |             |
                  v             v
               Use SAML     Can you choose your IdP?
               (or both)      |             |
                             YES           NO
                              |             |
                              v             v
                           Use OIDC     Use whatever
                                        the IdP supports
```

---

## Comparison: SSO Protocols at a Glance

| Criteria | SAML 2.0 | OAuth 2.0 | OpenID Connect |
|----------|---------|-----------|----------------|
| Primary purpose | Authentication + SSO | Authorization | Authentication + SSO |
| Token format | XML Assertion | Access Token (opaque/JWT) | ID Token (JWT) |
| User info delivery | In assertion | `/userinfo` endpoint | In ID Token + `/userinfo` |
| Enterprise ready | Yes (dominant) | Partial | Yes (growing) |
| Consumer ready | No | Yes | Yes |
| Complexity | High | Medium | Medium |
| Mobile support | Poor | Good | Excellent |
| Specification size | ~80 pages | ~75 pages | ~30 pages (builds on OAuth) |

---

## Summary

Single Sign-On is a fundamental component of modern identity architecture. It eliminates the burden of managing separate credentials for each application, centralizes security policy enforcement, and dramatically improves the user experience. SAML 2.0 remains entrenched in enterprise environments and will continue to be relevant for years, while OpenID Connect is the clear choice for new applications, mobile, and consumer-facing scenarios. In practice, supporting both protocols gives you the broadest compatibility. Regardless of which protocol you choose, the security of your SSO system hinges on protecting the Identity Provider, validating assertions rigorously, and implementing proper session management.

---

*Previous: [Access and Refresh Tokens](./06-access-refresh-tokens.md)*
