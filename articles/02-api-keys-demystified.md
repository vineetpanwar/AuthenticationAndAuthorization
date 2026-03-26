# API Keys Demystified: Simple Authentication for Service-to-Service Communication

*Estimated read time: 9 minutes*

---

You've probably used one before even thinking about it. You signed up for a service, navigated to a "Developer" or "API" section in the dashboard, clicked a button, and got a long random string. That string -- your **API key** -- became the password to the kingdom.

API keys are everywhere. Stripe uses them. Google Maps uses them. OpenAI uses them. If you've ever built anything that talks to a third-party service, you've held an API key in your hands.

But what exactly are they, how do they differ from the auth tokens we discussed in the previous article, and what are the rules for using them safely? Let's dig in.

---

## What Is an API Key?

An API key is a **unique identifier** assigned to a client application. Think of it as a membership card for software. It tells the server *which application* is calling, not necessarily *which user* is behind it.

This is the critical distinction: **API keys identify applications; auth tokens identify users.**

```
┌──────────────────────────────────────────────────┐
│              API Key vs Auth Token                │
├─────────────────────┬────────────────────────────┤
│      API Key        │       Auth Token           │
├─────────────────────┼────────────────────────────┤
│ Identifies the APP  │ Identifies the USER        │
│ "Which project?"    │ "Which person?"            │
│ Long-lived          │ Short-lived (usually)      │
│ One per project     │ One per session/user       │
│ Coarse permissions  │ Fine-grained permissions   │
└─────────────────────┴────────────────────────────┘
```

When Google Maps gets your API key, it knows "this request is coming from Vineet's food delivery app." It doesn't know (or care) which end-user is looking at the map.

---

## How API Keys Are Sent

There are three common ways to send an API key, and they are **not** equally safe.

### 1. As a Request Header (Recommended)

```http
GET /v1/charges HTTP/1.1
Host: api.stripe.com
Authorization: Bearer sk_test_abc123...
```

Or with a custom header:

```http
GET /v1/completions HTTP/1.1
Host: api.openai.com
Authorization: Bearer sk-abc123...
```

Some services use their own header names:

```http
GET /maps/api/geocode/json?address=NYC
Host: maps.googleapis.com
X-API-Key: AIzaSyD...
```

### 2. As a Query Parameter (Avoid if possible)

```
https://maps.googleapis.com/maps/api/js?key=AIzaSyD...
```

This works, but your key ends up in **browser history, server logs, referrer headers, and proxy logs**. It's like writing your house key number on a postcard.

### 3. In the Request Body (Rare)

```json
POST /api/action
{
  "api_key": "abc123...",
  "data": "some payload"
}
```

This is uncommon and generally not recommended. It mixes authentication with business logic.

### The Flow

```
┌───────────────┐                              ┌───────────────┐
│  Your App     │                              │  API Service   │
│  (Client)     │                              │  (Server)      │
└──────┬────────┘                              └──────┬────────┘
       │                                              │
       │  Request + API Key in header                 │
       │  X-API-Key: sk_test_abc123                   │
       │─────────────────────────────────────────────►│
       │                                              │
       │                          ┌───────────────────┤
       │                          │ 1. Look up key    │
       │                          │ 2. Check active?  │
       │                          │ 3. Check rate     │
       │                          │    limit          │
       │                          │ 4. Check perms    │
       │                          └───────────────────┤
       │                                              │
       │  200 OK  { "result": "..." }                 │
       │◄─────────────────────────────────────────────│
       │                                              │
```

---

## Rate Limiting and Permission Tiers

One of the most powerful things about API keys is that they make **rate limiting and tiering** trivial. The server maps your key to an account, and that account has a plan.

```
┌──────────────────────────────────────────────────┐
│              Typical API Key Tiers                │
├──────────┬───────────┬───────────┬───────────────┤
│  Tier    │ Rate Limit│   Cost    │  Features     │
├──────────┼───────────┼───────────┼───────────────┤
│  Free    │ 100/day   │   $0      │  Read-only    │
│  Pro     │ 10k/day   │  $49/mo   │  Read + Write │
│  Enterprise│ Unlimited│ Custom   │  Full access  │
└──────────┴───────────┴───────────┴───────────────┘
```

When your key hits the rate limit, you'll typically get a `429 Too Many Requests` response with a `Retry-After` header. No ambiguity, no guesswork.

---

## Real-World Examples

### Stripe

Stripe gives you two keys: a **publishable key** (safe for the frontend) and a **secret key** (backend only). The publishable key can only create tokens; the secret key can charge cards.

```
Publishable: pk_live_51J...   (frontend OK)
Secret:      sk_test_51J...   (backend ONLY)
```

### OpenAI

OpenAI uses a single API key per project, sent as a Bearer token:

```http
Authorization: Bearer sk-proj-abc123...
```

You can set spending limits and track usage per key -- crucial when GPT-4 calls cost real money.

### Google Maps

Google Maps keys are typically sent as query parameters (one of the rare cases where this is acceptable, since the key is restricted by HTTP referrer):

```
https://maps.googleapis.com/maps/api/js?key=AIzaSyD...
```

Google lets you restrict keys by **IP address, HTTP referrer, or API type** -- a critical security feature.

---

## Security Best Practices

API keys are simple, which means they're easy to misuse. Follow these rules:

### 1. Never Put Keys in URLs (If You Can Avoid It)
URLs get logged everywhere. Server access logs, browser history, analytics tools, proxy servers. A key in a URL is a key in the open.

### 2. Never Commit Keys to Version Control
This happens more often than anyone wants to admit. Use `.env` files and add them to `.gitignore`. Use a secrets manager in production.

```bash
# .env (NEVER commit this)
STRIPE_SECRET_KEY=sk_test_51J...
OPENAI_API_KEY=sk-proj-abc123...
```

### 3. Rotate Keys Regularly
Treat API keys like passwords. Rotate them quarterly, or immediately if you suspect exposure. Most services let you create multiple keys so you can rotate without downtime.

### 4. Use the Minimum Permissions Possible
If your key only needs to read data, don't give it write access. If it only needs access to one API, restrict it to that API.

### 5. Set Up Alerts for Unusual Usage
A sudden spike in API calls might mean your key was compromised. Most platforms offer usage monitoring -- use it.

### 6. Use Different Keys for Different Environments
Never use your production key in development. If your dev key leaks, your production data stays safe.

```
Development:  sk_test_abc123...
Staging:      sk_test_def456...
Production:   sk_test_ghi789...
```

---

## Key Takeaways

- API keys **identify applications**, not users. They're the "who's calling?" of the API world.
- Always send keys in **headers**, not URLs, when possible.
- They enable clean **rate limiting and permission tiering** out of the box.
- **Never commit keys to git.** Use environment variables and secrets managers.
- **Rotate regularly.** A key that never changes is a risk that only grows.
- Use **different keys** for dev, staging, and production environments.

---

## What's Next?

API keys are great for identifying applications, but what happens when you need to let a user grant your app access to *their* data on another service -- without sharing their password? That's the problem **OAuth 2.0** solves, and it's one of the most important protocols in modern authentication.

**Next up:** [OAuth 2.0: The Complete Guide to Delegated Authorization](./03-oauth2-the-complete-guide.md)
