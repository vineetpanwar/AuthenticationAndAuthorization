# Basic Auth vs Bearer Tokens: The Foundation of API Authentication

*Estimated read time: 12 minutes*

---

Every time you open an app, call an API, or log into a website, something invisible happens in milliseconds: **authentication**. The server needs to know who you are before it hands over any data. Get it wrong, and you're either locked out or -- worse -- someone else gets in.

If you've ever peeked at HTTP headers and wondered what `Authorization: Basic dXNlcjpwYXNz` or `Authorization: Bearer eyJhbGciOi...` actually means, this article is for you.

Let's break down the two most foundational authentication schemes on the web: **Basic Auth** and **Bearer Tokens**.

---

## What is Basic Auth?

Basic Authentication is the oldest and simplest HTTP authentication scheme. It was defined in the original HTTP/1.0 spec, and it still works today -- for better or worse.

Here's the deal: you take a username and password, glue them together with a colon, Base64-encode the result, and send it in every single request.

That's it. No tokens. No sessions. No handshakes.

### How It Works

```
Username: alice
Password: s3cret

Step 1: Combine       -> alice:s3cret
Step 2: Base64 encode -> YWxpY2U6czNjcmV0
Step 3: Send header   -> Authorization: Basic YWxpY2U6czNjcmV0
```

The server decodes the Base64 string, splits on the colon, and checks the credentials against its database.

### The Basic Auth Flow

```
┌──────────┐                           ┌──────────┐
│  Client   │                           │  Server   │
└─────┬────┘                           └─────┬────┘
      │                                       │
      │  GET /api/data                        │
      │  (no credentials)                     │
      │──────────────────────────────────────►│
      │                                       │
      │  401 Unauthorized                     │
      │  WWW-Authenticate: Basic realm="API"  │
      │◄──────────────────────────────────────│
      │                                       │
      │  GET /api/data                        │
      │  Authorization: Basic YWxpY2U6...     │
      │──────────────────────────────────────►│
      │                                       │
      │  200 OK                               │
      │  { "data": "here you go" }            │
      │◄──────────────────────────────────────│
      │                                       │
```

### What You Need to Know About Basic Auth

**It is NOT encrypted.** Base64 is an encoding, not encryption. Anyone who intercepts the header can decode your password in about two seconds. This means Basic Auth should **never** be used without HTTPS. Ever.

**Credentials travel with every request.** There's no session, no token -- the username and password are sent over the wire on every single API call. That's a lot of exposure.

**It's dead simple to implement.** And that's its main appeal. For internal tools, quick prototypes, or machine-to-machine communication behind a firewall, Basic Auth gets the job done with zero ceremony.

### A Real HTTP Request

```http
GET /api/v1/users HTTP/1.1
Host: api.example.com
Authorization: Basic YWxpY2U6czNjcmV0
Accept: application/json
```

---

## What are Bearer Tokens?

Bearer Tokens are the modern evolution. Instead of sending your actual credentials every time, you authenticate once and receive a **token** -- a string that proves you've already been verified.

The name says it all: whoever **bears** (carries) this token gets access. It's like a concert wristband -- the bouncer doesn't need to see your ID again; the wristband is proof enough.

### How It Works

```
Step 1: Client authenticates (login, OAuth, etc.)
Step 2: Server issues a token    -> "eyJhbGciOiJIUzI1NiIs..."
Step 3: Client stores the token
Step 4: Client sends it on every request ->
        Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

The server receives the token, validates it (checks signature, expiration, etc.), and grants access if everything checks out.

### The Bearer Token Flow

```
┌──────────┐                           ┌──────────┐
│  Client   │                           │  Server   │
└─────┬────┘                           └─────┬────┘
      │                                       │
      │  POST /auth/login                     │
      │  { "user": "alice", "pass": "..." }   │
      │──────────────────────────────────────►│
      │                                       │
      │  200 OK                               │
      │  { "token": "eyJhbGciOi..." }        │
      │◄──────────────────────────────────────│
      │                                       │
      │  GET /api/data                        │
      │  Authorization: Bearer eyJhbGciOi...  │
      │──────────────────────────────────────►│
      │                                       │
      │  200 OK                               │
      │  { "data": "here you go" }            │
      │◄──────────────────────────────────────│
      │                                       │
```

### Why Bearer Tokens Are Better (Usually)

**Credentials are sent only once.** Your password travels over the wire a single time -- during login. After that, only the token moves around.

**Tokens can expire.** A stolen token is bad, but a stolen token that expires in 15 minutes is much less bad than a stolen password that works forever.

**Tokens carry metadata.** A Bearer Token (especially a JWT) can contain information about the user, their roles, and what they're allowed to do -- without hitting the database.

**Tokens can be revoked.** Changed your password? Detected suspicious activity? Invalidate the token. With Basic Auth, you'd have to change the password itself.

### A Real HTTP Request

```http
GET /api/v1/users HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkw...
Accept: application/json
```

---

## Side-by-Side Comparison

```
┌──────────────────────┬─────────────────────┬───────────────────────┐
│                      │    Basic Auth        │    Bearer Tokens      │
├──────────────────────┼─────────────────────┼───────────────────────┤
│ What's sent          │ Username + Password  │ Opaque/signed token   │
│ Encoding             │ Base64               │ Varies (often JWT)    │
│ Credentials exposed  │ Every request        │ Only at login         │
│ Stateless?           │ Yes                  │ Yes (if JWT)          │
│ Can expire?          │ No (password-based)  │ Yes (token TTL)       │
│ Revocable?           │ Change password only │ Revoke token          │
│ Complexity           │ Very low             │ Moderate              │
│ Best for             │ Internal/simple APIs │ Public-facing APIs    │
│ Requires HTTPS?      │ Absolutely           │ Absolutely            │
└──────────────────────┴─────────────────────┴───────────────────────┘
```

---

## When to Use Each

### Use Basic Auth When:

- You're building **internal tools** behind a VPN or firewall
- You need a **quick prototype** and security isn't the top concern yet
- The API is for **machine-to-machine** communication in a trusted environment
- You're integrating with a **legacy system** that only supports Basic Auth

### Use Bearer Tokens When:

- You're building a **public-facing API**
- You need **fine-grained expiration** and revocation
- Your architecture is **microservices-based** and tokens need to flow between services
- You want **stateless authentication** (no server-side session storage)
- You're implementing **OAuth 2.0** (which uses Bearer Tokens by design)

---

## Common Mistakes to Avoid

1. **Using Basic Auth without HTTPS.** I cannot stress this enough. Base64 is not a security measure.
2. **Storing Bearer Tokens in localStorage.** They're vulnerable to XSS attacks. Use httpOnly cookies when possible.
3. **Never expiring tokens.** A token that lives forever is just a password with extra steps.
4. **Hardcoding credentials in source code.** Use environment variables or a secrets manager.

---

## Key Takeaways

- **Basic Auth** sends Base64-encoded credentials on every request. Simple, but risky without HTTPS.
- **Bearer Tokens** decouple authentication from every request. More secure, more flexible.
- Both require HTTPS. No exceptions.
- Basic Auth works for internal/simple use cases. Bearer Tokens are the standard for modern APIs.
- Neither is inherently "better" -- context determines the right choice.

---

## What's Next?

Now that you understand the two foundational authentication headers, it's time to explore another common approach: **API Keys**. They sit somewhere between Basic Auth and Bearer Tokens in terms of complexity and are wildly popular for service-to-service communication.

**Next up:** [API Keys Demystified: Simple Authentication for Service-to-Service Communication](./02-api-keys-demystified.md)
