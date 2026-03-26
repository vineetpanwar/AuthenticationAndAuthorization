# Single Sign-On Explained: One Login to Rule Them All

*Estimated read time: 12 minutes*

---

Picture a typical morning at a large company. You open your laptop, log in once, and then seamlessly access your email, your project management tool, the HR portal, the company wiki, and the internal analytics dashboard. No second password prompt. No "sign in again" pop-ups. One login, and you're in everywhere.

That's **Single Sign-On (SSO)**, and enterprises are obsessed with it for good reason.

SSO isn't just about convenience -- it's about security, compliance, and sanity. When employees use 20+ different apps and each requires a separate login, they reuse passwords, write them on sticky notes, and create security nightmares. SSO eliminates all of that.

---

## How SSO Works: The Big Picture

At its core, SSO introduces a **central authority** that handles authentication for multiple applications. Instead of each app managing its own username/password database, they all delegate authentication to a single trusted service.

```
┌────────────────────────────────────────────────────────────┐
│                    Without SSO                              │
│                                                             │
│  ┌───────┐  login  ┌─────────┐                             │
│  │ User  ├────────►│ Email   │  (own user database)        │
│  │       ├────────►│ Slack   │  (own user database)        │
│  │       ├────────►│ Jira    │  (own user database)        │
│  │       ├────────►│ Wiki    │  (own user database)        │
│  └───────┘         └─────────┘                             │
│  4 apps = 4 logins = 4 passwords = chaos                   │
├────────────────────────────────────────────────────────────┤
│                    With SSO                                 │
│                                                             │
│  ┌───────┐  login  ┌──────────┐  trust  ┌─────────┐       │
│  │ User  ├────────►│ Identity │◄───────►│ Email   │       │
│  └───────┘  (once) │ Provider │◄───────►│ Slack   │       │
│                     │ (IdP)    │◄───────►│ Jira    │       │
│                     │          │◄───────►│ Wiki    │       │
│                     └──────────┘         └─────────┘       │
│  4 apps = 1 login = 1 password = order                     │
└────────────────────────────────────────────────────────────┘
```

The central service is called an **Identity Provider (IdP)**. The applications that rely on it are called **Service Providers (SPs)** or **Relying Parties (RPs)**.

---

## Key Terminology

```
┌────────────────────┬────────────────────────────────────────┐
│ Term               │ Meaning                                │
├────────────────────┼────────────────────────────────────────┤
│ Identity Provider  │ The service that authenticates users   │
│ (IdP)              │ and vouches for their identity.        │
│                    │ Examples: Okta, Azure AD, Google       │
│                    │ Workspace, Auth0                       │
├────────────────────┼────────────────────────────────────────┤
│ Service Provider   │ The application that trusts the IdP    │
│ (SP)               │ and grants access based on its         │
│                    │ assertion. Examples: Slack, Salesforce, │
│                    │ your internal apps                     │
├────────────────────┼────────────────────────────────────────┤
│ Assertion          │ A signed statement from the IdP that   │
│                    │ says "yes, this user is who they claim │
│                    │ to be."                                │
├────────────────────┼────────────────────────────────────────┤
│ Session            │ Once SSO authenticates a user, a       │
│                    │ session cookie is set. Subsequent app  │
│                    │ accesses reuse this session.           │
└────────────────────┴────────────────────────────────────────┘
```

---

## The Two Protocols: SAML 2.0 vs OpenID Connect

There are two dominant SSO protocols. Both achieve the same goal but in very different ways.

### SAML 2.0 (Security Assertion Markup Language)

SAML has been around since 2005 and is the **enterprise workhorse**. It uses XML-based assertions and is deeply entrenched in corporate environments.

**How the SAML SSO flow works:**

```
┌──────────┐        ┌──────────────┐        ┌──────────────┐
│  User     │        │  Service      │        │  Identity    │
│ (Browser) │        │  Provider     │        │  Provider    │
│           │        │  (e.g. Slack) │        │  (e.g. Okta) │
└────┬─────┘        └──────┬───────┘        └──────┬───────┘
     │                      │                       │
     │ 1. Access Slack      │                       │
     │─────────────────────►│                       │
     │                      │                       │
     │ 2. Not logged in!    │                       │
     │    Redirect to IdP   │                       │
     │    (SAML AuthnReq)   │                       │
     │◄─────────────────────│                       │
     │                      │                       │
     │ 3. Follow redirect   │                       │
     │──────────────────────────────────────────────►│
     │                      │                       │
     │ 4. IdP login page    │                       │
     │◄──────────────────────────────────────────────│
     │                      │                       │
     │ 5. Enter credentials │                       │
     │──────────────────────────────────────────────►│
     │                      │                       │
     │ 6. Credentials OK!   │                       │
     │    Redirect back     │                       │
     │    with SAML Response│                       │
     │    (signed XML)      │                       │
     │◄──────────────────────────────────────────────│
     │                      │                       │
     │ 7. POST SAML Response│                       │
     │─────────────────────►│                       │
     │                      │                       │
     │              ┌───────┤                       │
     │              │Verify │                       │
     │              │XML sig│                       │
     │              └───────┤                       │
     │                      │                       │
     │ 8. Welcome to Slack! │                       │
     │◄─────────────────────│                       │
     │                      │                       │
```

**Key characteristics of SAML:**
- XML-based (verbose but well-established)
- Uses browser redirects and POST requests
- Assertions are digitally signed
- Designed for **web browsers** (not great for mobile/APIs)
- Ubiquitous in enterprise software

### OpenID Connect (OIDC)

OIDC is the modern alternative, built **on top of OAuth 2.0**. It adds an identity layer to OAuth's authorization framework. If OAuth answers "what can this app do?", OIDC answers "who is this user?"

**How the OIDC flow works:**

```
┌──────────┐        ┌──────────────┐        ┌──────────────┐
│  User     │        │  App          │        │  OIDC        │
│ (Browser) │        │ (Relying      │        │  Provider    │
│           │        │  Party)       │        │  (e.g Google)│
└────┬─────┘        └──────┬───────┘        └──────┬───────┘
     │                      │                       │
     │ 1. "Login with       │                       │
     │    Google"           │                       │
     │─────────────────────►│                       │
     │                      │                       │
     │ 2. Redirect to       │                       │
     │    Google OIDC       │                       │
     │◄─────────────────────│                       │
     │                      │                       │
     │ 3. Authenticate with Google                  │
     │──────────────────────────────────────────────►│
     │                      │                       │
     │ 4. Consent + redirect back with AUTH CODE    │
     │◄──────────────────────────────────────────────│
     │                      │                       │
     │ 5. Send code to app  │                       │
     │─────────────────────►│                       │
     │                      │                       │
     │                      │ 6. Exchange code for  │
     │                      │    ID Token + Access  │
     │                      │    Token              │
     │                      │──────────────────────►│
     │                      │                       │
     │                      │ 7. Tokens returned    │
     │                      │    (ID Token = JWT!)  │
     │                      │◄──────────────────────│
     │                      │                       │
     │ 8. Logged in!        │                       │
     │◄─────────────────────│                       │
     │                      │                       │
```

The magic is in the **ID Token** -- a JWT that contains the user's identity information:

```json
{
  "iss": "https://accounts.google.com",
  "sub": "1234567890",
  "aud": "your-app-client-id",
  "email": "alice@gmail.com",
  "name": "Alice Smith",
  "picture": "https://...",
  "iat": 1616239022,
  "exp": 1616242622
}
```

**Key characteristics of OIDC:**
- JSON-based (lightweight, modern)
- Built on OAuth 2.0 (uses the same flows)
- ID Token is a JWT
- Works well for **web, mobile, and APIs**
- Growing rapidly in adoption

---

## SAML vs OIDC: When to Use Which

```
┌──────────────────────┬───────────────────┬───────────────────┐
│                      │    SAML 2.0       │    OIDC           │
├──────────────────────┼───────────────────┼───────────────────┤
│ Format               │ XML               │ JSON / JWT        │
│ Built on             │ Its own spec      │ OAuth 2.0         │
│ Age                  │ 2005              │ 2014              │
│ Best for             │ Enterprise web    │ Modern apps,      │
│                      │ apps              │ mobile, APIs      │
│ Token type           │ SAML Assertion    │ ID Token (JWT)    │
│ Mobile support       │ Poor              │ Excellent         │
│ Complexity           │ High              │ Moderate          │
│ Enterprise adoption  │ Very high         │ Growing fast      │
│ Example IdPs         │ Okta, ADFS,       │ Google, Auth0,    │
│                      │ PingFederate      │ Okta, Azure AD    │
└──────────────────────┴───────────────────┴───────────────────┘
```

**Rule of thumb:** If you're integrating with legacy enterprise systems, you'll likely encounter SAML. If you're building something new, go with OIDC.

Many modern IdPs (Okta, Azure AD, Auth0) support both protocols, so the choice often depends on what the Service Provider supports.

---

## Real-World SSO Providers

### Google Workspace
Google acts as both an IdP and an SP. As an IdP, it provides SSO for thousands of third-party apps. Employees log into Google once and get access to Gmail, Drive, Calendar, plus any SAML/OIDC-integrated third-party apps.

### Okta
Okta is a pure-play IdP. It doesn't have its own email or productivity tools -- its entire purpose is identity management. Okta's dashboard becomes the single place where employees access all their apps.

### Azure Active Directory (Azure AD / Entra ID)
Microsoft's identity platform. If your company uses Microsoft 365, Azure AD is likely your IdP. It integrates deeply with the Microsoft ecosystem and supports SAML, OIDC, and WS-Federation.

---

## The SSO Session: How "One Login" Works

When you authenticate with the IdP, it sets a **session cookie** in your browser for the IdP's domain. Here's why subsequent app accesses don't require re-login:

```
┌──────────────────────────────────────────────────────────┐
│               How SSO Session Reuse Works                 │
│                                                           │
│  1. User accesses App A                                   │
│     --> Redirect to IdP                                   │
│     --> User logs in                                      │
│     --> IdP sets session cookie: idp.example.com          │
│     --> Redirect back to App A with assertion             │
│     --> User is in!                                       │
│                                                           │
│  2. User accesses App B                                   │
│     --> Redirect to IdP                                   │
│     --> Browser sends existing IdP session cookie         │
│     --> IdP sees valid session, NO LOGIN NEEDED           │
│     --> Redirect back to App B with assertion             │
│     --> User is in! (without typing any password)         │
│                                                           │
│  3. User accesses App C                                   │
│     --> Same as above. Session cookie does the work.      │
│                                                           │
└──────────────────────────────────────────────────────────┘
```

The user only entered credentials once (for App A). Every subsequent app just piggybacks on the existing IdP session.

---

## Why Enterprises Love SSO

1. **Security.** One strong password (+ MFA) instead of dozens of weak ones. Centralized access control means disabling one account revokes access everywhere.

2. **Compliance.** Auditors love centralized authentication logs. "Show me who accessed what and when" becomes a single query.

3. **User Experience.** Employees access everything with one click. No password fatigue.

4. **IT Efficiency.** Onboarding means creating one IdP account. Offboarding means disabling it. Every connected app is instantly affected.

5. **Reduced Help Desk Load.** "I forgot my password" tickets drop dramatically when there's only one password to remember.

---

## Common SSO Pitfalls

### Single Point of Failure
If the IdP goes down, nobody can log in to anything. Mitigate this with IdP redundancy and cached sessions.

### Logout Complexity
Logging out of one app should log you out of all apps (Single Logout / SLO). This is surprisingly hard to implement correctly, especially with SAML.

### Session Length Mismatches
If the IdP session lasts 8 hours but the app session lasts 1 hour, users might be confused about when they need to re-authenticate.

### Over-Reliance on SSO
If SSO is the only security layer, compromising one account compromises everything. Always pair SSO with **Multi-Factor Authentication (MFA)**.

---

## Key Takeaways

- **SSO** lets users authenticate once and access multiple applications without re-entering credentials.
- The **Identity Provider (IdP)** handles authentication; **Service Providers (SPs)** trust its assertions.
- **SAML 2.0** is the enterprise veteran (XML-based, web-focused). **OIDC** is the modern choice (JSON/JWT, works everywhere).
- SSO works via **session cookies** on the IdP's domain. After the first login, the browser proves the user's session automatically.
- Always pair SSO with **MFA**. One login to rule them all also means one compromised password to lose them all.

---

## What's Next?

So far, we've focused on **authentication** -- proving who you are. But once you're in, who decides what you can do? Can you edit, or only view? Can you access the admin panel? That's **authorization**, and the most popular model for handling it is **Role-Based Access Control (RBAC)**.

**Next up:** [RBAC: The Most Popular Authorization Model and How to Implement It](./07-rbac-guide.md)
