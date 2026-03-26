# JWT Deep Dive: Understanding JSON Web Tokens from the Inside Out

*Estimated read time: 15 minutes*

---

You've been using them in every `Authorization: Bearer` header. OAuth gives them to you. Your middleware validates them. But have you ever stopped to actually decode one and understand what's inside?

A JSON Web Token (JWT, pronounced "jot") is not a black box. It's a carefully structured, cryptographically signed string that carries information between two parties. And once you understand its anatomy, the entire world of modern authentication starts to make a lot more sense.

Let's crack one open.

---

## What Is a JWT?

A JWT is a compact, URL-safe way to represent **claims** -- statements about an entity (typically a user) and additional metadata. The key property of a JWT is that it's **self-contained**: the token itself carries all the information needed to validate it.

No database lookup required. No session store. The token *is* the proof.

Here's what one looks like in the wild:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiaWF0IjoxNjE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

Looks like gibberish? Look closer. There are exactly **two dots** splitting this into three parts.

---

## The Three Parts of a JWT

```
┌─────────────────────────────────────────────────────────┐
│                     JWT Structure                        │
│                                                          │
│   HEADER          PAYLOAD          SIGNATURE             │
│  (Algorithm)    (The Claims)     (Verification)          │
│                                                          │
│  eyJhbGci...  .  eyJzdWIi...  .  SflKxwRJ...           │
│  ─────────────  ──────────────  ──────────────          │
│  Base64URL       Base64URL       Base64URL               │
│                                                          │
│  {"alg":"HS256", {"sub":"1234",  HMACSHA256(            │
│   "typ":"JWT"}    "name":"Alice", header + "." +        │
│                   "iat":16162..}   payload,              │
│                                    secret)               │
└─────────────────────────────────────────────────────────┘
```

### Part 1: The Header

The header is a JSON object that tells you two things: the **token type** and the **signing algorithm**.

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

This gets Base64URL-encoded to become the first segment:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

Common algorithms:
- `HS256` -- HMAC with SHA-256 (symmetric, shared secret)
- `RS256` -- RSA with SHA-256 (asymmetric, public/private key pair)
- `ES256` -- ECDSA with SHA-256 (asymmetric, elliptic curve)

### Part 2: The Payload

The payload is where the actual data lives. It contains **claims** -- key-value pairs that make statements about the user and the token itself.

```json
{
  "sub": "1234567890",
  "name": "Alice",
  "email": "alice@example.com",
  "role": "admin",
  "iat": 1616239022,
  "exp": 1616242622
}
```

Base64URL-encoded:

```
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIiwiZW1haWwiOiJhbGljZUBleGFtcGxlLmNvbSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTYxNjIzOTAyMiwiZXhwIjoxNjE2MjQyNjIyfQ
```

**Important: The payload is encoded, not encrypted.** Anyone with a JWT can decode the payload and read its contents. Never put sensitive information (passwords, credit card numbers, secrets) in a JWT.

### Part 3: The Signature

The signature is what makes JWTs trustworthy. It ensures the token hasn't been tampered with.

For HMAC-SHA256, the signature is created like this:

```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

The server that created the token holds the `secret`. When it receives a JWT later, it recalculates the signature. If the recalculated signature matches the one in the token, the token is legitimate.

If anyone changes even a single character in the header or payload, the signature won't match, and the token is rejected.

---

## How Signing Works: HMAC vs RSA

This is where things get interesting. There are two fundamentally different approaches to signing JWTs.

### HMAC (Symmetric) -- HS256

```
┌───────────┐                           ┌───────────┐
│  Service A │                           │  Service B │
│  (Creator) │                           │ (Verifier) │
└─────┬─────┘                           └─────┬─────┘
      │                                       │
      │  Uses SHARED SECRET to sign           │
      │  ┌──────────────────────┐             │
      │  │ secret = "my-secret" │             │
      │  └──────────────────────┘             │
      │                                       │
      │          JWT Token                    │
      │──────────────────────────────────────►│
      │                                       │
      │          Uses SAME SECRET to verify   │
      │          ┌──────────────────────┐     │
      │          │ secret = "my-secret" │     │
      │          └──────────────────────┘     │
      │                                       │
```

**One secret, shared by both sides.** Simple, fast, but both parties need the same secret. If you have 10 microservices, all 10 need the secret -- and any one of them can create new tokens.

### RSA (Asymmetric) -- RS256

```
┌───────────┐                           ┌───────────┐
│  Auth      │                           │  Any       │
│  Server    │                           │  Service   │
└─────┬─────┘                           └─────┬─────┘
      │                                       │
      │  Uses PRIVATE KEY to sign             │
      │  ┌──────────────────────┐             │
      │  │ private_key (secret) │             │
      │  └──────────────────────┘             │
      │                                       │
      │          JWT Token                    │
      │──────────────────────────────────────►│
      │                                       │
      │          Uses PUBLIC KEY to verify    │
      │          ┌──────────────────────┐     │
      │          │ public_key (shared)  │     │
      │          └──────────────────────┘     │
      │                                       │
```

**Two keys: private for signing, public for verifying.** Only the auth server holds the private key, so only it can create tokens. Any service can verify tokens using the public key -- but they can't forge new ones.

This is the standard for microservices architectures. The public key is typically published at a well-known URL (a JWKS endpoint):

```
https://auth.example.com/.well-known/jwks.json
```

---

## Claims: The Payload's Vocabulary

Claims are organized into three categories:

### Registered Claims (Standard)

These are predefined by the JWT spec (RFC 7519). They're not required, but they're strongly recommended:

```
┌────────┬──────────────────────────────────────────────┐
│ Claim  │ Meaning                                      │
├────────┼──────────────────────────────────────────────┤
│ iss    │ Issuer -- who created the token              │
│ sub    │ Subject -- who the token is about            │
│ aud    │ Audience -- who the token is intended for    │
│ exp    │ Expiration -- when the token expires (Unix)  │
│ nbf    │ Not Before -- token not valid before this    │
│ iat    │ Issued At -- when the token was created      │
│ jti    │ JWT ID -- unique identifier for the token    │
└────────┴──────────────────────────────────────────────┘
```

### Public Claims

Custom claims that are either registered in the IANA JWT Claims Registry or use collision-resistant names (like URIs):

```json
{
  "https://example.com/roles": ["admin", "editor"]
}
```

### Private Claims

Custom claims agreed upon between the parties. This is where most application-specific data lives:

```json
{
  "role": "admin",
  "team_id": "team_abc123",
  "permissions": ["read", "write", "delete"]
}
```

---

## Stateless Authentication with JWTs

This is the killer feature. Traditional session-based auth requires the server to store session data. JWTs flip this on its head.

```
┌─────────────────────────────────────────────────────────┐
│          Session-Based vs JWT Authentication             │
│                                                          │
│  SESSION-BASED:                                          │
│  ┌────────┐   session_id    ┌────────┐   lookup    ┌──┐│
│  │ Client ├────────────────►│ Server ├────────────►│DB││
│  └────────┘                 └────────┘             └──┘│
│  Server must store session data. Every request = DB hit│
│                                                          │
│  JWT-BASED:                                              │
│  ┌────────┐   JWT token     ┌────────┐                  │
│  │ Client ├────────────────►│ Server │  (no DB needed!) │
│  └────────┘                 └────────┘                  │
│  Token IS the session. Server just validates signature. │
└─────────────────────────────────────────────────────────┘
```

With JWTs, the server:
1. Receives the token
2. Verifies the signature
3. Reads the claims (user ID, role, etc.)
4. Serves the request

No database hit. No session store. No Redis. The token carries everything.

This is why JWTs are beloved in **microservices** -- each service can independently validate tokens without shared state.

---

## JWT Validation Flow

```
┌──────────┐                              ┌──────────┐
│  Client   │                              │  Server   │
└─────┬────┘                              └─────┬────┘
      │                                         │
      │  GET /api/data                          │
      │  Authorization: Bearer eyJhbG...        │
      │────────────────────────────────────────►│
      │                                         │
      │                    ┌────────────────────┤
      │                    │                    │
      │                    │  1. Split token    │
      │                    │     into 3 parts   │
      │                    │                    │
      │                    │  2. Decode header  │
      │                    │     -> get alg     │
      │                    │                    │
      │                    │  3. Recalculate    │
      │                    │     signature      │
      │                    │                    │
      │                    │  4. Compare with   │
      │                    │     token sig      │
      │                    │     MATCH? ──► OK  │
      │                    │     NO MATCH? ──►  │
      │                    │       REJECT       │
      │                    │                    │
      │                    │  5. Check exp      │
      │                    │     Expired? ──►   │
      │                    │       REJECT       │
      │                    │                    │
      │                    │  6. Check iss, aud │
      │                    │     Wrong? ──►     │
      │                    │       REJECT       │
      │                    │                    │
      │                    │  7. Extract claims │
      │                    │     (sub, role...) │
      │                    └────────────────────┤
      │                                         │
      │  200 OK / 401 Unauthorized              │
      │◄────────────────────────────────────────│
      │                                         │
```

---

## Common Pitfalls and Security Concerns

### 1. The `alg: none` Attack

Some JWT libraries accept tokens with `"alg": "none"` -- meaning no signature at all. An attacker can modify the payload, set the algorithm to `none`, and bypass verification entirely.

**Fix:** Always validate the algorithm on the server side. Never accept `none`.

### 2. Algorithm Confusion (RS256 vs HS256)

If your server expects RS256 (asymmetric), an attacker might send a token signed with HS256 using the **public key** as the secret. Since the public key is, well, public, the attacker can forge valid tokens.

**Fix:** Explicitly specify which algorithm your server accepts. Never let the token dictate the algorithm.

### 3. Not Validating Expiration

If you don't check the `exp` claim, tokens live forever. A stolen token is a permanently stolen identity.

**Fix:** Always validate `exp`. Set short expiration times (15-60 minutes).

### 4. Storing Sensitive Data in the Payload

Remember: the payload is Base64-encoded, **not encrypted**. Anyone can decode it.

```bash
echo "eyJzdWIiOiIxMjM0NTY3ODkwIn0" | base64 -d
# {"sub":"1234567890"}
```

**Fix:** Never put passwords, secrets, or PII in JWTs. If you must include sensitive data, use JWE (JSON Web Encryption) instead.

### 5. JWTs Can't Be Revoked (Easily)

This is the trade-off of statelessness. Once issued, a JWT is valid until it expires. You can't "log out" a JWT the way you can delete a session.

**Workarounds:**
- Keep expiration times short
- Maintain a blocklist of revoked token IDs (`jti`)
- Use refresh token rotation (covered in the next article)

### 6. Token Size

JWTs can get large, especially with many claims. Every request carries the full token. A 2KB JWT on every API call adds up.

**Fix:** Keep payloads lean. Only include what's necessary.

---

## When to Use JWTs (And When Not To)

**Use JWTs when:**
- You have a microservices architecture and need stateless auth
- You want to pass user context between services without shared state
- You need the token to carry information (claims)
- You're implementing OAuth 2.0 or OpenID Connect

**Don't use JWTs when:**
- You need instant revocation (sessions are better)
- You're storing large amounts of data (use a database)
- Your system is a simple monolith with a session store already in place

---

## Key Takeaways

- A JWT has three Base64URL-encoded parts: **Header**, **Payload**, and **Signature**, separated by dots.
- The payload is **encoded, not encrypted**. Don't put secrets in it.
- **HMAC** (symmetric) uses a shared secret; **RSA** (asymmetric) uses a public/private key pair.
- JWTs enable **stateless authentication** -- no database lookups needed for validation.
- Always validate: the **signature**, the **algorithm**, the **expiration**, and the **audience**.
- JWTs trade **revocability for scalability**. Keep expiration times short.

---

## What's Next?

We've mentioned that JWTs should be short-lived. But if an access token expires every 15 minutes, does the user have to log in again every 15 minutes? No -- and that's where **refresh tokens** come in.

**Next up:** [Access Tokens and Refresh Tokens: The Art of Staying Logged In Securely](./05-access-refresh-tokens.md)
