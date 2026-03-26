# Basic Authentication

## Introduction

Basic Authentication is the simplest form of HTTP authentication, defined in **RFC 7617**. It transmits credentials as a Base64-encoded string in the `Authorization` header of every HTTP request. Despite its simplicity, it remains widely used in internal APIs, development environments, and scenarios where transport-layer encryption (TLS/HTTPS) is enforced.

The core idea is straightforward: the client sends a username and password with each request, and the server validates them before granting access to the requested resource.

> **Key Principle:** Basic Authentication is *stateless* -- the server does not maintain any session. Every request must carry the full credentials.

---

## How It Works (Step-by-Step)

1. **Client makes a request** to a protected resource without credentials.
2. **Server responds with `401 Unauthorized`** and includes a `WWW-Authenticate: Basic realm="..."` header.
3. **Client prompts the user** for a username and password (or retrieves them from configuration).
4. **Client encodes the credentials** by concatenating `username:password` and Base64-encoding the result.
5. **Client resends the request** with the header: `Authorization: Basic <Base64-encoded-credentials>`.
6. **Server decodes the Base64 string**, extracts the username and password, and validates them against its credential store.
7. **If valid**, the server returns the requested resource with a `200 OK`.
8. **If invalid**, the server returns `401 Unauthorized` again.

### Example

```
Username: admin
Password: s3cret

Concatenated: admin:s3cret
Base64 Encoded: YWRtaW46czNjcmV0

Header: Authorization: Basic YWRtaW46czNjcmV0
```

---

## Flow Diagram

```
 CLIENT                                           SERVER
   |                                                 |
   |  1. GET /api/resource                           |
   | ----------------------------------------------> |
   |                                                 |
   |  2. 401 Unauthorized                            |
   |     WWW-Authenticate: Basic realm="Secure API"  |
   | <---------------------------------------------- |
   |                                                 |
   |  [Client encodes username:password as Base64]   |
   |                                                 |
   |  3. GET /api/resource                           |
   |     Authorization: Basic YWRtaW46czNjcmV0       |
   | ----------------------------------------------> |
   |                                                 |
   |     +----------------------------------+        |
   |     |  SERVER VALIDATION STEPS:        |        |
   |     |  a. Decode Base64 string         |        |
   |     |  b. Split on first ":"           |        |
   |     |  c. Lookup user in credential DB |        |
   |     |  d. Compare password (hashed)    |        |
   |     +----------------------------------+        |
   |                                                 |
   |  4a. 200 OK  (credentials valid)               |
   |      { "data": "protected resource" }           |
   | <---------------------------------------------- |
   |                                                 |
   |  --- OR ---                                     |
   |                                                 |
   |  4b. 401 Unauthorized (credentials invalid)     |
   | <---------------------------------------------- |
   |                                                 |


   Subsequent Requests (credentials sent EVERY time):

   |  5. GET /api/another-resource                   |
   |     Authorization: Basic YWRtaW46czNjcmV0       |
   | ----------------------------------------------> |
   |                                                 |
   |  6. 200 OK                                      |
   | <---------------------------------------------- |
```

---

## Encoding Detail (Not Encryption!)

```
  +---------------------+        +---------------------------+
  |  Plain Text Input   |        |   Base64 Output           |
  |  "admin:s3cret"     | -----> |   "YWRtaW46czNjcmV0"     |
  +---------------------+        +---------------------------+

  WARNING: Base64 is ENCODING, not ENCRYPTION.
           Anyone who intercepts the header can decode it instantly:

  $ echo "YWRtaW46czNjcmV0" | base64 --decode
  admin:s3cret
```

---

## Pros and Cons

| Pros | Cons |
|------|------|
| Extremely simple to implement | Credentials sent with **every** request |
| Supported by virtually all HTTP clients | Base64 is **not encryption** -- trivially decoded |
| No session management needed | No built-in mechanism for logout |
| Works well for server-to-server calls | Vulnerable to brute-force attacks without rate limiting |
| Stateless -- scales horizontally easily | Password must be stored or accessible on client side |
| Universally supported in browsers | Browser credential caching behavior is inconsistent |

---

## Real-World Use Cases

- **Internal microservice communication** behind a firewall where TLS is enforced.
- **CI/CD pipelines** accessing private package registries (e.g., npm, Maven).
- **Development and testing environments** where simplicity trumps security.
- **IoT devices** with constrained capabilities that cannot handle complex auth flows.
- **Legacy system integration** where more modern auth is not supported.
- **CLI tools** like `curl` where quick, scriptable authentication is needed.

---

## When to Use

- You need the simplest possible authentication mechanism.
- Communication is **always** over HTTPS/TLS.
- The client is a trusted server or internal service, not a public-facing application.
- You are prototyping or building a proof of concept.
- The API has very low sensitivity requirements.

## When NOT to Use

- Public-facing web applications where users authenticate via a browser.
- Any scenario where traffic might traverse an unencrypted channel.
- When you need fine-grained authorization (scopes, roles, permissions).
- When you need token expiration or revocation capabilities.
- Mobile applications where storing plaintext credentials is risky.
- High-security environments (banking, healthcare, government).

---

## Security Considerations

### 1. Always Use HTTPS
Since credentials are only Base64-encoded (not encrypted), they are readable in plaintext to anyone intercepting the traffic. **HTTPS is non-negotiable.**

### 2. Rate Limiting and Brute-Force Protection
Implement rate limiting on authentication endpoints. Consider lockout policies after repeated failed attempts.

### 3. Credential Storage
- **Server side:** Never store passwords in plaintext. Use bcrypt, scrypt, or Argon2 for hashing.
- **Client side:** Store credentials in secure vaults (e.g., OS keychain, HashiCorp Vault), never in source code.

### 4. Credential Rotation
Establish policies for regular password rotation. Automate this process where possible.

### 5. Logging
Never log the `Authorization` header value. Ensure that proxy servers and load balancers are configured to strip or mask sensitive headers in logs.

### 6. Replay Attacks
Basic Auth is inherently vulnerable to replay attacks. Mitigate by:
- Enforcing HTTPS
- Using short-lived credentials where possible
- Implementing request signing alongside Basic Auth

---

## Comparison with Other Methods

| Feature | Basic Auth | Bearer Token | API Key | OAuth 2.0 |
|---------|-----------|-------------|---------|-----------|
| Complexity | Very Low | Low | Low | High |
| Credentials per request | Yes | Yes (token) | Yes (key) | Yes (token) |
| Built-in expiration | No | Optional | No | Yes |
| Revocation support | No (change password) | Yes | Yes | Yes |
| Granular permissions | No | Optional | Optional | Yes (scopes) |
| Suitable for browsers | Minimal | Yes | No | Yes |
| Standardized | RFC 7617 | RFC 6750 | No standard | RFC 6749 |

---

## Code Examples

### Server-Side Validation (Pseudocode)

```python
def authenticate(request):
    auth_header = request.headers.get("Authorization")

    if not auth_header or not auth_header.startswith("Basic "):
        return Response(status=401, headers={
            "WWW-Authenticate": 'Basic realm="Secure API"'
        })

    # Decode the Base64 credentials
    encoded_credentials = auth_header.split(" ", 1)[1]
    decoded = base64.b64decode(encoded_credentials).decode("utf-8")
    username, password = decoded.split(":", 1)

    # Validate against the credential store
    user = database.find_user(username)
    if user and bcrypt.verify(password, user.hashed_password):
        return handle_request(request, user)

    return Response(status=401, headers={
        "WWW-Authenticate": 'Basic realm="Secure API"'
    })
```

### Client-Side Request (cURL)

```bash
# Explicit header
curl -H "Authorization: Basic $(echo -n 'admin:s3cret' | base64)" \
     https://api.example.com/resource

# Shorthand (-u flag)
curl -u admin:s3cret https://api.example.com/resource
```

---

## Summary

Basic Authentication is the "hello world" of HTTP authentication. It is easy to implement, universally supported, and perfectly adequate for low-risk, internal, or development scenarios **as long as HTTPS is enforced**. However, for anything involving end users, sensitive data, or public-facing APIs, you should graduate to token-based authentication (Bearer, JWT) or delegated authorization frameworks (OAuth 2.0).

---

*Next: [Bearer Token Authentication](./02-bearer-tokens.md)*
