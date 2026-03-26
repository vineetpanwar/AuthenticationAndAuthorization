# OAuth 2.0: The Complete Guide to Delegated Authorization

*Estimated read time: 15 minutes*

---

Imagine you're building a cool new app that helps people organize their Google Drive files. To do that, your app needs access to their Drive. The obvious (and terrible) approach? Ask users for their Google username and password.

This is exactly what apps used to do. And it was a nightmare.

You'd store someone's Google password, have full access to their entire account (not just Drive), and if your app got hacked, every user's Google account was compromised. There was no way to limit access, no way to revoke it cleanly, and no way for Google to tell the difference between the real user and your app.

**OAuth 2.0 was created to solve this problem.** It lets users grant your application limited access to their data on another service -- without ever sharing their password.

It's the protocol behind every "Login with Google," "Sign in with GitHub," and "Connect your Slack" button you've ever clicked.

---

## The Four Roles of OAuth 2.0

Before we dive into flows and tokens, you need to meet the four actors in every OAuth story:

```
┌─────────────────────────────────────────────────────────────┐
│                   The Four OAuth Roles                       │
├─────────────────┬───────────────────────────────────────────┤
│ Resource Owner   │ The user. The human who owns the data.   │
│                  │ Example: You, with your Google account.   │
├─────────────────┼───────────────────────────────────────────┤
│ Client           │ The app requesting access.                │
│                  │ Example: The Drive organizer app.         │
├─────────────────┼───────────────────────────────────────────┤
│ Authorization    │ The server that authenticates the user    │
│ Server           │ and issues tokens.                        │
│                  │ Example: accounts.google.com              │
├─────────────────┼───────────────────────────────────────────┤
│ Resource Server  │ The API that holds the protected data.    │
│                  │ Example: drive.googleapis.com             │
└─────────────────┴───────────────────────────────────────────┘
```

In many implementations (like Google's), the Authorization Server and Resource Server are run by the same company. But conceptually, they're separate roles.

---

## The Authorization Code Flow (The Gold Standard)

This is the most common and most secure OAuth 2.0 flow. It's what happens when you click "Login with Google" on a web application.

Let's walk through it step by step.

### The Flow

```
┌──────────┐       ┌──────────┐       ┌──────────────┐       ┌──────────────┐
│  User     │       │  Client   │       │  Auth Server  │       │  Resource    │
│ (Browser) │       │  (App)    │       │  (Google)     │       │  Server      │
└────┬─────┘       └────┬─────┘       └──────┬───────┘       └──────┬───────┘
     │                   │                     │                      │
     │ 1. Click          │                     │                      │
     │ "Login with       │                     │                      │
     │  Google"          │                     │                      │
     │──────────────────►│                     │                      │
     │                   │                     │                      │
     │   2. Redirect to Google                 │                      │
     │◄──────────────────│                     │                      │
     │                   │                     │                      │
     │ 3. User logs in + consents              │                      │
     │────────────────────────────────────────►│                      │
     │                   │                     │                      │
     │ 4. Redirect back with AUTH CODE         │                      │
     │◄────────────────────────────────────────│                      │
     │                   │                     │                      │
     │ 5. Send auth code │                     │                      │
     │──────────────────►│                     │                      │
     │                   │                     │                      │
     │                   │ 6. Exchange code     │                      │
     │                   │    for tokens        │                      │
     │                   │    (+ client secret) │                      │
     │                   │────────────────────►│                      │
     │                   │                     │                      │
     │                   │ 7. Access Token      │                      │
     │                   │    + Refresh Token   │                      │
     │                   │◄────────────────────│                      │
     │                   │                     │                      │
     │                   │ 8. API call with     │                      │
     │                   │    Access Token      │                      │
     │                   │─────────────────────────────────────────►│
     │                   │                     │                      │
     │                   │ 9. Protected data    │                      │
     │                   │◄─────────────────────────────────────────│
     │                   │                     │                      │
     │ 10. Show data     │                     │                      │
     │◄──────────────────│                     │                      │
     │                   │                     │                      │
```

### Step by Step

**Step 1-2: The Redirect.** When the user clicks "Login with Google," your app redirects them to Google's authorization endpoint with specific parameters:

```
https://accounts.google.com/o/oauth2/v2/auth?
  response_type=code
  &client_id=YOUR_CLIENT_ID
  &redirect_uri=https://yourapp.com/callback
  &scope=https://www.googleapis.com/auth/drive.readonly
  &state=random_csrf_token
```

Key parameters:
- `response_type=code` -- We want an authorization code
- `client_id` -- Your app's public identifier (registered with Google)
- `redirect_uri` -- Where to send the user after they consent
- `scope` -- What access you're requesting (just read-only Drive access)
- `state` -- A random value to prevent CSRF attacks

**Step 3: User Consents.** Google shows the user a consent screen: "Drive Organizer App wants to view your Google Drive files. Allow?" The user clicks "Allow."

**Step 4: The Authorization Code.** Google redirects back to your `redirect_uri` with a short-lived authorization code:

```
https://yourapp.com/callback?code=4/0AY0e-g7...&state=random_csrf_token
```

**Step 5-6: Code Exchange.** Your backend server exchanges the authorization code for tokens. This happens server-to-server -- the user's browser never sees it:

```http
POST /token HTTP/1.1
Host: oauth2.googleapis.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=4/0AY0e-g7...
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
&redirect_uri=https://yourapp.com/callback
```

**Step 7: Tokens.** Google responds with an access token (and usually a refresh token):

```json
{
  "access_token": "ya29.a0AfH6SM...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "1//0gdN...",
  "scope": "https://www.googleapis.com/auth/drive.readonly"
}
```

**Steps 8-10: Use the Token.** Your app uses the access token to call Google's APIs:

```http
GET /drive/v3/files HTTP/1.1
Host: www.googleapis.com
Authorization: Bearer ya29.a0AfH6SM...
```

---

## Why the Authorization Code? Why Not Send the Token Directly?

Great question. The extra step exists for security.

The authorization code travels through the **user's browser** (via the redirect URL). If Google sent the access token directly, it would be exposed in the browser's address bar, history, and referrer headers.

Instead, the short-lived code is exchanged for tokens through a **secure server-to-server call** that includes the `client_secret` -- something that never touches the browser.

---

## Other Grant Types

The Authorization Code flow is the gold standard, but OAuth 2.0 defines several others for different scenarios:

### Client Credentials Grant
For **machine-to-machine** communication where no user is involved. Your server authenticates directly with the auth server using its own credentials.

```
Your Server --> Auth Server: "Here's my client_id and client_secret"
Auth Server --> Your Server: "Here's an access token"
```

Use case: Your backend service accessing another internal API.

### Authorization Code with PKCE
The Authorization Code flow adapted for **mobile and single-page apps** that can't safely store a `client_secret`. PKCE (Proof Key for Code Exchange) adds a dynamically generated secret to prevent authorization code interception.

Use case: Mobile apps, browser-based SPAs.

### Device Authorization Grant
For devices with **limited input** (smart TVs, CLI tools). The device shows a code, the user enters it on their phone or laptop.

```
Smart TV: "Go to https://google.com/device and enter code: WDJB-MJHT"
User: *enters code on phone, logs in, grants access*
Smart TV: *polls auth server until approved*
```

Use case: Streaming devices, IoT, CLI tools.

### Implicit Grant (Deprecated)
Used to send the access token directly in the redirect URL. **Don't use this.** It's been superseded by Authorization Code with PKCE.

---

## Scopes: Limiting Access

Scopes are one of OAuth's superpowers. They let the user grant **limited access** -- not all-or-nothing.

```
┌──────────────────────────────────────────────┐
│           Example Google Scopes              │
├─────────────────────────┬────────────────────┤
│ Scope                   │ What It Grants     │
├─────────────────────────┼────────────────────┤
│ drive.readonly          │ View files         │
│ drive.file              │ View + edit files  │
│ gmail.send              │ Send emails        │
│ calendar.events         │ Manage calendar    │
│ userinfo.email          │ Read email address │
│ userinfo.profile        │ Read basic profile │
└─────────────────────────┴────────────────────┘
```

Always request the **minimum scopes** your app needs. Users trust apps that ask for less.

---

## Real-World: "Login with Google"

When you see a "Login with Google" button, here's what's actually happening under the hood:

1. The app registered with Google and got a `client_id` and `client_secret`
2. Clicking the button triggers the Authorization Code flow
3. Google handles the login UI, passwords, and 2FA
4. Your app gets an access token scoped to `userinfo.email` and `userinfo.profile`
5. Your app calls Google's userinfo endpoint to get the user's name and email
6. Your app creates or finds the matching user in its own database
7. Your app creates its own session/token for the user

The app **never sees the user's Google password**. Google handles all of that.

---

## Common Pitfalls

1. **Not validating the `state` parameter.** This opens you up to CSRF attacks. Always generate a random state, store it in the session, and verify it in the callback.

2. **Storing tokens insecurely.** Access tokens in localStorage are vulnerable to XSS. Use httpOnly cookies or secure server-side storage.

3. **Requesting too many scopes.** Users will deny your app if it asks for access to their email, contacts, calendar, and files when it only needs their profile picture.

4. **Not using PKCE for public clients.** If you're building a mobile or SPA app, PKCE is not optional -- it's essential.

5. **Confusing authentication with authorization.** OAuth 2.0 is an *authorization* framework. For authentication, you need OpenID Connect (an identity layer built on top of OAuth).

---

## Key Takeaways

- OAuth 2.0 solves the **delegated authorization** problem: letting apps access your data without your password.
- The **Authorization Code flow** is the most secure and common pattern.
- The authorization code acts as an intermediary so tokens never touch the browser.
- **Scopes** limit what an app can do with your data. Always request the minimum.
- OAuth 2.0 is for **authorization**. For authentication (proving who someone is), you need OpenID Connect on top.
- **PKCE** is mandatory for mobile and browser-based apps.

---

## What's Next?

You've seen that OAuth issues "access tokens" -- but what's actually inside those tokens? Most modern implementations use **JSON Web Tokens (JWTs)**, and understanding their structure is crucial for building secure systems.

**Next up:** [JWT Deep Dive: Understanding JSON Web Tokens from the Inside Out](./04-jwt-deep-dive.md)
