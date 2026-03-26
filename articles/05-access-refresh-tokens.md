# Access Tokens and Refresh Tokens: The Art of Staying Logged In Securely

*Estimated read time: 12 minutes*

---

Here's a dilemma that every authentication system faces.

If your access token lives for a year, you only need to log in once -- convenient. But if someone steals that token, they have a year to wreak havoc. If your token expires every 5 minutes, it's incredibly secure -- but your users will rage-quit after the 50th login prompt in a single afternoon.

How do you stay logged in for weeks without giving attackers a permanent key to your account?

The answer is a two-token system: **short-lived access tokens** paired with **long-lived refresh tokens**. It's one of the most elegant patterns in authentication, and once you understand it, you'll see it everywhere.

---

## The Core Idea

```
┌──────────────────────────────────────────────────────────────┐
│                   The Two-Token System                        │
│                                                               │
│  ┌─────────────────────┐    ┌──────────────────────────┐     │
│  │    ACCESS TOKEN      │    │     REFRESH TOKEN         │     │
│  ├─────────────────────┤    ├──────────────────────────┤     │
│  │ Lives: 15-60 min    │    │ Lives: days to weeks      │     │
│  │ Used: Every API call│    │ Used: Only to get new     │     │
│  │ Stored: Memory      │    │       access tokens       │     │
│  │ Sent to: Resource   │    │ Stored: Secure storage    │     │
│  │         servers     │    │ Sent to: Auth server ONLY │     │
│  │ Revocable: Hard     │    │ Revocable: Easy           │     │
│  └─────────────────────┘    └──────────────────────────┘     │
│                                                               │
│  Think of it like this:                                       │
│  Access Token  = Hotel room key card (expires daily)          │
│  Refresh Token = Your reservation (lasts the whole trip)      │
└──────────────────────────────────────────────────────────────┘
```

The **access token** is your working credential. It's what you attach to every API request. It's short-lived -- typically 15 to 60 minutes.

The **refresh token** is your backup. When the access token expires, you send the refresh token to the authorization server and get a fresh access token. The user never has to re-enter their password.

---

## The Refresh Flow

Let's walk through the entire lifecycle.

```
┌──────────┐                    ┌──────────────┐             ┌──────────────┐
│  Client   │                    │  Auth Server  │             │  Resource    │
│  (App)    │                    │               │             │  Server      │
└─────┬────┘                    └──────┬───────┘             └──────┬───────┘
      │                                │                            │
      │ 1. POST /auth/login            │                            │
      │    { user, password }          │                            │
      │───────────────────────────────►│                            │
      │                                │                            │
      │ 2. Here's both tokens          │                            │
      │    { access_token (15m),       │                            │
      │      refresh_token (7d) }      │                            │
      │◄───────────────────────────────│                            │
      │                                │                            │
      │ 3. GET /api/data               │                            │
      │    Authorization: Bearer       │                            │
      │    <access_token>              │                            │
      │────────────────────────────────────────────────────────────►│
      │                                │                            │
      │ 4. 200 OK { data }            │                            │
      │◄────────────────────────────────────────────────────────────│
      │                                │                            │
      │                                │                            │
      │    ~~~ 15 minutes pass ~~~     │                            │
      │                                │                            │
      │                                │                            │
      │ 5. GET /api/data               │                            │
      │    Authorization: Bearer       │                            │
      │    <expired_access_token>      │                            │
      │────────────────────────────────────────────────────────────►│
      │                                │                            │
      │ 6. 401 Token Expired           │                            │
      │◄────────────────────────────────────────────────────────────│
      │                                │                            │
      │ 7. POST /auth/refresh          │                            │
      │    { refresh_token }           │                            │
      │───────────────────────────────►│                            │
      │                                │                            │
      │ 8. NEW tokens!                 │                            │
      │    { access_token (15m),       │                            │
      │      refresh_token (7d) }      │                            │
      │◄───────────────────────────────│                            │
      │                                │                            │
      │ 9. Retry with new token        │                            │
      │    GET /api/data               │                            │
      │    Authorization: Bearer       │                            │
      │    <new_access_token>          │                            │
      │────────────────────────────────────────────────────────────►│
      │                                │                            │
      │ 10. 200 OK { data }           │                            │
      │◄────────────────────────────────────────────────────────────│
      │                                │                            │
```

The user logged in once (Step 1) and never had to again. Behind the scenes, the app silently refreshed the token when it expired. From the user's perspective, they just stayed logged in.

---

## Token Rotation: The Security Upgrade

Here's where things get clever. The most secure implementations use **refresh token rotation**: every time a refresh token is used, a new one is issued and the old one is invalidated.

```
Login:
  Access Token #1  (15 min)
  Refresh Token #1 (7 days)

After 15 minutes:
  Use Refresh Token #1 --> Get:
    Access Token #2  (15 min)
    Refresh Token #2 (7 days)    <-- #1 is now INVALID

After another 15 minutes:
  Use Refresh Token #2 --> Get:
    Access Token #3  (15 min)
    Refresh Token #3 (7 days)    <-- #2 is now INVALID
```

Each refresh token is single-use. The moment it's redeemed, it's dead. This creates a chain where only the latest token is valid.

But why bother? Because of what happens when tokens get stolen.

---

## Token Theft Detection

Refresh token rotation enables a powerful security feature: **automatic theft detection**.

Consider this scenario:

```
Timeline:
─────────────────────────────────────────────────────────

1. User logs in, gets Refresh Token #1

2. Attacker steals Refresh Token #1

3. Attacker uses Refresh Token #1
   --> Gets Access Token + Refresh Token #2
   --> Refresh Token #1 is now invalidated

4. Real user tries to use Refresh Token #1
   --> SERVER SEES: a revoked token being reused!
   --> ALARM: possible token theft!
   --> Server invalidates ALL tokens in the family
   --> Both user AND attacker are logged out
   --> User must re-authenticate
```

The server maintains a **token family** -- a lineage of refresh tokens all stemming from the original login. If a revoked token from that family is ever used again, the server knows something is wrong and nukes the entire family.

This is called **automatic reuse detection**, and it's the industry best practice.

```
┌──────────────────────────────────────────────────────┐
│              Token Family & Reuse Detection           │
│                                                       │
│  Login ──► RT#1 ──► RT#2 ──► RT#3 ──► RT#4          │
│             │        │        │        │              │
│           (used)   (used)   (used)  (current)        │
│                                                       │
│  If RT#2 is used again:                               │
│  "Wait, RT#2 was already redeemed for RT#3..."       │
│  "Someone must have stolen it!"                       │
│  --> REVOKE EVERYTHING: RT#3, RT#4, and all           │
│      associated access tokens                         │
│                                                       │
└──────────────────────────────────────────────────────┘
```

---

## Where to Store Tokens

Token storage is a contentious topic. Here's the practical guidance:

### Web Applications

| Storage Method | Access Token | Refresh Token |
|----------------|-------------|---------------|
| **Memory (JS variable)** | Best option. Gone on page refresh, but safe from XSS. | No -- lost on refresh. |
| **httpOnly Cookie** | Good. Server-set, inaccessible to JS. | Best option. Secure, httpOnly, SameSite. |
| **localStorage** | Risky. Accessible to any JS on the page (XSS). | Never. |
| **sessionStorage** | Slightly better than localStorage. | Never. |

The gold standard for web apps:
- **Access token** in memory (a JavaScript variable)
- **Refresh token** in an httpOnly, Secure, SameSite=Strict cookie

This means if the page refreshes, the access token is gone -- but the app can silently call the refresh endpoint (using the cookie) to get a new one.

### Mobile Applications

Use the platform's secure storage:
- **iOS:** Keychain
- **Android:** Encrypted SharedPreferences or Keystore

Never store tokens in plain text files or unencrypted databases.

---

## Implementation Best Practices

### 1. Keep Access Tokens Short-Lived
15 minutes is a common choice. Some high-security systems go as low as 5 minutes. The shorter the lifetime, the smaller the window of exploitation if a token is stolen.

### 2. Refresh Tokens Should Be Opaque
Unlike access tokens (which are often JWTs with readable claims), refresh tokens should be **opaque random strings** stored in the server's database. There's no reason for the client to read the contents.

```
Access Token:  eyJhbGciOiJSUzI1NiIsInR5cCI6...  (JWT - readable)
Refresh Token: dGhpcyBpcyBhIHJlZnJlc2ggdG9r...  (opaque - meaningless to client)
```

### 3. Bind Refresh Tokens to the Client
Store metadata alongside the refresh token: device fingerprint, IP range, user agent. If a refresh request comes from a wildly different context, reject it.

### 4. Implement Token Families
Track the lineage of refresh tokens. If a token that's already been used shows up again, revoke the entire family.

### 5. Set Absolute Expiration
Even with rotation, set a maximum lifetime for a refresh token chain. After 30 days (or whatever your policy is), force a re-login. This limits the damage of undetected theft.

### 6. Handle Failures Gracefully
When a refresh fails (expired, revoked, or suspicious), redirect the user to login. Don't retry in a loop -- it's almost certainly not a transient error.

---

## The Complete Token Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│   User Login                                                 │
│       │                                                      │
│       ▼                                                      │
│   ┌───────────┐                                              │
│   │ Auth      │──► Issues Access Token (AT#1) + Refresh     │
│   │ Server    │    Token (RT#1)                               │
│   └───────────┘                                              │
│       │                                                      │
│       ▼                                                      │
│   ┌─── Normal Operation Loop ─────────────────────────────┐ │
│   │                                                        │ │
│   │  Client uses AT to call APIs                           │ │
│   │       │                                                │ │
│   │       ▼                                                │ │
│   │  AT Expired?                                           │ │
│   │  ├── No  ──► Continue using AT                         │ │
│   │  └── Yes ──► Use RT to get new AT + RT                 │ │
│   │              ├── Success ──► Loop back                  │ │
│   │              └── Failure ──► Force re-login             │ │
│   │                                                        │ │
│   └────────────────────────────────────────────────────────┘ │
│       │                                                      │
│       ▼                                                      │
│   User Logs Out                                              │
│   ──► Revoke RT, discard AT                                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Key Takeaways

- **Access tokens** are short-lived (minutes) and used for every API call.
- **Refresh tokens** are long-lived (days/weeks) and used only to get new access tokens.
- **Token rotation** means each refresh token is single-use. Old ones are invalidated.
- **Reuse detection** catches token theft: if a revoked refresh token is used again, nuke the entire token family.
- Store access tokens in **memory**, refresh tokens in **httpOnly cookies** (web) or **secure storage** (mobile).
- Always set an **absolute maximum lifetime** for refresh token chains.

---

## What's Next?

You now understand how individual users authenticate and stay logged in. But in enterprise environments, users don't want to log in separately to every app -- they want to log in once and access everything. That's **Single Sign-On (SSO)**.

**Next up:** [Single Sign-On Explained: One Login to Rule Them All](./06-sso-explained.md)
