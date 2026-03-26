# Digest Authentication

## Overview

Digest Authentication is an HTTP authentication scheme defined in **RFC 2617** (1999) and updated in **RFC 7616** (2015). It was designed to address the primary weakness of Basic Auth: sending passwords in plaintext (Base64 is encoding, not encryption).

Instead of transmitting the password, Digest Auth sends a **cryptographic hash** (called a "digest") that proves the client knows the password — without ever revealing it on the wire.

## How It Works

### The Challenge-Response Flow

```
Client                                 Server
  |                                      |
  |  1. GET /protected                   |
  |  ─────────────────────────────────>  |
  |                                      |
  |  2. 401 Unauthorized                 |
  |     WWW-Authenticate: Digest         |
  |       realm="example.com"            |
  |       nonce="dcd98b..."              |
  |       qop="auth"                     |
  |       algorithm=MD5                  |
  |  <─────────────────────────────────  |
  |                                      |
  |  [Client computes hash]              |
  |  HA1 = MD5(user:realm:password)      |
  |  HA2 = MD5(GET:/protected)           |
  |  resp = MD5(HA1:nonce:nc:cnonce:     |
  |             qop:HA2)                 |
  |                                      |
  |  3. GET /protected                   |
  |     Authorization: Digest            |
  |       username="alice"               |
  |       realm="example.com"            |
  |       nonce="dcd98b..."              |
  |       uri="/protected"               |
  |       nc=00000001                    |
  |       cnonce="0a4f113b"              |
  |       qop=auth                       |
  |       response="6629fae4..."         |
  |  ─────────────────────────────────>  |
  |                                      |
  |  [Server computes same hash          |
  |   and compares]                      |
  |                                      |
  |  4. 200 OK                           |
  |     { "message": "Welcome!" }        |
  |  <─────────────────────────────────  |
```

### The Hash Computation

**Step 1 — HA1 (Identity Hash):**
```
HA1 = MD5(username : realm : password)
    = MD5("alice:example.com:password123")
    = "a1b2c3d4e5f6..."
```

**Step 2 — HA2 (Request Hash):**
```
HA2 = MD5(method : digestURI)
    = MD5("GET:/protected")
    = "f7e8d9c0b1a2..."
```

**Step 3 — Response (Final Digest):**
```
response = MD5(HA1 : nonce : nc : cnonce : qop : HA2)
         = MD5("a1b2c3...:dcd98b...:00000001:0a4f113b:auth:f7e8d9...")
         = "6629fae49393..."
```

## Key Fields Explained

| Field | Purpose | Who generates it |
|-------|---------|-----------------|
| **realm** | Protection space identifier | Server |
| **nonce** | One-time server value (prevents replay) | Server |
| **nc** | Nonce count — incremented per request | Client |
| **cnonce** | Client nonce (prevents chosen-plaintext attacks) | Client |
| **qop** | "auth" (authentication) or "auth-int" (+integrity) | Server declares, client selects |
| **opaque** | Server state echoed back unchanged | Server |
| **algorithm** | Hash function: MD5 (default) or SHA-256 | Server |

## Basic Auth vs Digest Auth

| Feature | Basic Auth | Digest Auth |
|---------|-----------|-------------|
| Password sent over wire | Yes (Base64) | No (only hash) |
| Replay protection | None | Nonce + nc counter |
| HTTPS required | Absolutely | Still recommended |
| Server stores password as | Hash (bcrypt OK) | Plaintext or HA1 hash |
| Implementation complexity | Very simple | Moderate |
| Browser support | Universal | Universal |
| RFC | 7617 | 7616 |

## Security Considerations

### Advantages
- Password never traverses the network
- Nonce prevents replay attacks
- Nonce count (nc) detects replayed requests
- Client nonce (cnonce) prevents server-side chosen-plaintext attacks

### Limitations
- Server must store passwords in reversible form (or HA1 hashes) — no bcrypt
- MD5 is cryptographically broken (use SHA-256 per RFC 7616)
- Vulnerable to MITM that downgrades to Basic Auth (without HTTPS)
- More complex than modern token-based approaches
- No built-in session management

## When to Use Digest Auth

**Good for:**
- Legacy systems that cannot use HTTPS
- IoT devices with limited TLS capability
- Upgrading from Basic Auth with minimal changes
- HTTP-based protocols (SIP, RTSP) that adopted Digest natively

**Better alternatives exist:**
- For web APIs → Bearer tokens or API keys over HTTPS
- For user login → OAuth 2.0 / OpenID Connect
- For maximum security → Mutual TLS or Passkeys

## Running the Demo

```bash
npm run digest-auth

# Test with curl (--digest flag handles the challenge-response automatically)
curl --digest -u alice:password123 http://localhost:3012/protected
curl --digest -u bob:secret456 http://localhost:3012/admin
```

## References

- [RFC 2617 — HTTP Authentication: Basic and Digest](https://tools.ietf.org/html/rfc2617)
- [RFC 7616 — HTTP Digest Access Authentication (2015 update)](https://tools.ietf.org/html/rfc7616)
- [RFC 7235 — HTTP/1.1 Authentication](https://tools.ietf.org/html/rfc7235)
