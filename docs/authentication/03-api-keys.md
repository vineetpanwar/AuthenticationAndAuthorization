# API Key Authentication

## Introduction

API Key Authentication is one of the most widely adopted methods for identifying and authenticating applications (rather than individual users) that access an API. An API key is a unique string -- typically a long, randomly generated alphanumeric token -- that the client includes with each request to identify itself.

Unlike Basic Authentication, which authenticates a *person*, API keys typically authenticate an *application* or *project*. They answer the question: "Which application is making this request?" rather than "Which user is making this request?"

API keys are everywhere: Google Maps, Stripe, OpenAI, SendGrid, Twilio, AWS -- virtually every developer-facing platform issues API keys. Their popularity stems from their simplicity: generate a key, pass it in the header or query parameter, and you are authenticated.

---

## How It Works (Step-by-Step)

1. **Developer registers** an application on the API provider's developer portal.
2. **API provider generates** a unique API key (and optionally a secret key) and presents it to the developer.
3. **Developer stores** the API key securely in their application configuration.
4. **Client sends the API key** with each request -- typically in a header, query parameter, or request body.
5. **API server extracts the key**, looks it up in its database, and validates it.
6. **If valid**, the server identifies the associated application/project, applies rate limits and permissions, and processes the request.
7. **If invalid or missing**, the server returns `401 Unauthorized` or `403 Forbidden`.

---

## Flow Diagram

```
  DEVELOPER PORTAL                CLIENT APP                    API SERVER
       |                              |                              |
       |  1. Register Application     |                              |
       | <--------------------------- |                              |
       |                              |                              |
       |  2. Issue API Key            |                              |
       |     Key: "sk_test_example_key" |                              |
       | ---------------------------> |                              |
       |                              |                              |
       |    [Developer stores key     |                              |
       |     in env vars / vault]     |                              |
       |                              |                              |
       |                              |  3. GET /api/v1/data         |
       |                              |     X-API-Key: sk_test_examp |
       |                              | ---------------------------> |
       |                              |                              |
       |                              |     +----------------------+ |
       |                              |     | API SERVER:           | |
       |                              |     | a. Extract key from   | |
       |                              |     |    header             | |
       |                              |     | b. Lookup key in DB   | |
       |                              |     | c. Check key status:  | |
       |                              |     |    - Active?          | |
       |                              |     |    - Rate limit OK?   | |
       |                              |     |    - Permissions?     | |
       |                              |     | d. Log usage metrics  | |
       |                              |     +----------------------+ |
       |                              |                              |
       |                              |  4. 200 OK                  |
       |                              |     { "data": [...] }       |
       |                              | <--------------------------- |
       |                              |                              |


  Common API Key Transmission Methods:

  Method 1: Custom Header (RECOMMENDED)
  +---------------------------------------------+
  | GET /api/data HTTP/1.1                       |
  | Host: api.example.com                        |
  | X-API-Key: sk_test_example_key_1234567890   |
  +---------------------------------------------+

  Method 2: Authorization Header
  +---------------------------------------------+
  | GET /api/data HTTP/1.1                       |
  | Host: api.example.com                        |
  | Authorization: ApiKey sk_test_example_...     |
  +---------------------------------------------+

  Method 3: Query Parameter (AVOID in production)
  +---------------------------------------------+
  | GET /api/data?api_key=sk_test_example_key...  |
  | Host: api.example.com                        |
  +---------------------------------------------+

  Method 4: Request Body
  +---------------------------------------------+
  | POST /api/data HTTP/1.1                      |
  | Host: api.example.com                        |
  | Content-Type: application/json               |
  |                                              |
  | { "api_key": "sk_test_examp...", ... }       |
  +---------------------------------------------+
```

---

## API Key Anatomy and Best Practices

```
  Stripe-Style Key Structure:
  +--------+--------+----------------------------------+
  | Prefix | Mode   |         Random Portion           |
  +--------+--------+----------------------------------+
  | sk_    | live_  | 4eC39HqLyjWDarjtT1zdp7dc        |
  | pk_    | test_  | 51SeGhPesQ9rn8KLwEq2xA           |
  +--------+--------+----------------------------------+
    |         |
    |         +-- Indicates environment (live vs test)
    +------------ Indicates key type (secret vs public)

  Key Generation Best Practices:
  +--------------------------------------------------+
  | - Use cryptographically secure random generation  |
  | - Minimum 32 bytes of entropy (256 bits)         |
  | - Use URL-safe characters (alphanumeric + _-)    |
  | - Include a recognizable prefix for key type     |
  | - Store hashed version server-side               |
  | - Show full key to developer only ONCE at        |
  |   creation time                                  |
  +--------------------------------------------------+
```

---

## API Key vs. API Key + Secret (HMAC Signing)

```
  Simple API Key:
  +--------------------+
  | Client sends key   |         Server checks key
  | in every request   | ------> against database
  +--------------------+

  API Key + Secret (HMAC):
  +------------------------------------+
  | Client uses SECRET to create HMAC  |
  | signature of request content.      |
  | Sends API KEY + SIGNATURE.         |
  +------------------------------------+
         |
         v
  +------------------------------------+
  | Server looks up secret by API Key. |
  | Recomputes HMAC signature.         |
  | Compares signatures.               |
  +------------------------------------+

  Benefit: The secret never travels over the network.
  Used by: AWS (Signature V4), payment processors.
```

---

## Pros and Cons

| Pros | Cons |
|------|------|
| Very simple to implement and use | Identifies applications, not users (no user context) |
| Easy for developers to understand | Keys are long-lived -- high impact if leaked |
| Good for usage tracking and rate limiting | No built-in expiration mechanism |
| Can be scoped to specific permissions | Difficult to rotate without downtime |
| Works across all HTTP client types | No standard specification (implementations vary) |
| Enables per-application billing and metering | Keys in query parameters leak in logs and referrer headers |
| Easy to revoke and regenerate | Cannot convey complex authorization claims |

---

## Real-World Use Cases

- **Third-party API access** -- Google Maps, OpenAI, Stripe, and Twilio all use API keys for developer access.
- **Usage metering and billing** -- API keys tie requests to billing accounts (pay-per-call models).
- **Rate limiting** -- Different keys can have different rate limits based on subscription tier.
- **Public data APIs** -- Weather APIs, geocoding services, and public datasets use API keys for tracking without requiring full authentication.
- **Webhooks** -- Verifying that incoming webhook payloads come from a trusted source.
- **Server-to-server communication** -- Backend services communicating with external APIs.

---

## When to Use

- You need to identify and meter application-level access (not individual users).
- You are building a developer platform or public API.
- You need simple, low-friction access control.
- Rate limiting and usage tracking are primary concerns.
- The API serves data that is not user-specific or highly sensitive.

## When NOT to Use

- You need to authenticate individual users (use OAuth 2.0 or JWT instead).
- You need fine-grained, per-user authorization.
- The API handles highly sensitive user data (financial, medical).
- You need token expiration and automatic rotation.
- Client-side applications (SPAs, mobile apps) where the key would be exposed in source code.

---

## Security Considerations

### 1. Never Expose Keys in Client-Side Code
API keys embedded in JavaScript, mobile apps, or public repositories are trivially extractable. Use backend proxies for client-facing applications.

```
  BAD:  Frontend JS --> API (key in JS source -- anyone can see it)

  GOOD: Frontend JS --> Your Backend (session auth) --> API (key on server)
```

### 2. Use HTTPS Always
API keys in plaintext over HTTP are visible to anyone on the network path.

### 3. Hash Keys Server-Side
Store a hashed version of the key in your database (similar to password storage). Only show the full key to the developer at creation time.

### 4. Implement Key Rotation
- Support multiple active keys per application to allow zero-downtime rotation.
- Provide a grace period where old and new keys both work.
- Send automated alerts when keys are approaching a recommended rotation age.

### 5. Restrict Key Scope
- Limit keys by HTTP method (read-only vs. read-write).
- Limit keys by endpoint or resource.
- Limit keys by IP address or CIDR range.
- Limit keys by referrer domain (for browser-based usage).

### 6. Monitor and Alert
- Log all API key usage with timestamps, IP addresses, and endpoints accessed.
- Alert on anomalous patterns (sudden spike in requests, requests from new geographies).
- Provide developers with usage dashboards.

### 7. Prevent Key Leakage
- Use secret scanning tools (GitHub secret scanning, git-secrets, truffleHog) to detect committed keys.
- Invalidate keys immediately if they appear in public repositories.
- Services like GitHub and GitLab automatically notify API providers when keys are detected in public repos.

---

## Comparison: API Key Delivery Methods

| Method | Security | Cacheability | Log Safety | Recommendation |
|--------|----------|-------------|------------|----------------|
| Custom header (`X-API-Key`) | High | Not cached | Safe (headers typically not logged) | **Recommended** |
| `Authorization` header | High | Not cached | Safe | Good alternative |
| Query parameter | Low | Cached in browser history | **Leaks in server logs** | **Avoid** |
| Request body | Medium | Not cached | Depends on logging config | POST-only, not ideal |
| Cookie | Medium | Cached by browser | Depends on config | Not standard for API keys |

---

## Key Management Lifecycle

```
  +-------------+     +-------------+     +-------------+
  |   CREATE    | --> |   ACTIVE    | --> |   ROTATE    |
  |             |     |             |     |             |
  | - Generate  |     | - In use    |     | - New key   |
  |   random key|     | - Tracked   |     |   generated |
  | - Hash &    |     | - Metered   |     | - Grace     |
  |   store     |     | - Monitored |     |   period    |
  | - Show once |     |             |     |             |
  +-------------+     +------+------+     +------+------+
                             |                    |
                             v                    v
                      +-------------+     +-------------+
                      |   SUSPEND   |     |   REVOKE    |
                      |             |     |             |
                      | - Temporary |     | - Permanent |
                      |   disable   |     | - Old key   |
                      | - Can be    |     |   invalid   |
                      |   reactivated     | - Audit log |
                      +-------------+     +-------------+
```

---

## Code Example

### Server-Side Validation (Pseudocode)

```python
import hashlib
import secrets

# Key generation
def generate_api_key(prefix="sk_test_"):
    random_part = secrets.token_urlsafe(32)
    full_key = f"{prefix}{random_part}"
    hashed_key = hashlib.sha256(full_key.encode()).hexdigest()

    # Store hashed_key in database
    database.store(hashed_key=hashed_key, metadata={...})

    # Return full_key to developer (show only once!)
    return full_key

# Key validation middleware
def validate_api_key(request):
    api_key = request.headers.get("X-API-Key")

    if not api_key:
        return Response(status=401, body={"error": "API key required"})

    hashed_key = hashlib.sha256(api_key.encode()).hexdigest()
    key_record = database.find(hashed_key=hashed_key)

    if not key_record or key_record.status != "active":
        return Response(status=403, body={"error": "Invalid API key"})

    # Check rate limits
    if rate_limiter.is_exceeded(key_record.id):
        return Response(status=429, body={"error": "Rate limit exceeded"})

    # Log usage
    metrics.record(key_id=key_record.id, endpoint=request.path)

    request.app_context = key_record.metadata
    return handle_request(request)
```

---

## Summary

API keys are the standard mechanism for application-level authentication and metering. They are simple, widely understood, and effective for their intended purpose: identifying *which application* is calling your API. However, they are not a substitute for user authentication. For user-specific access, combine API keys (for application identity) with OAuth 2.0 or JWT (for user identity). Always transmit keys in headers over HTTPS, hash them server-side, and implement robust rotation and monitoring practices.

---

*Previous: [Bearer Token Authentication](./02-bearer-tokens.md) | Next: [OAuth 2.0](./04-oauth2.md)*
