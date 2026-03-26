# Authentication & Authorization - Complete Guide

![Node.js](https://img.shields.io/badge/Node.js-v18+-green?logo=node.js)
![Express](https://img.shields.io/badge/Express-4.x-blue?logo=express)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Auth Methods](https://img.shields.io/badge/Auth_Methods-8-orange)
![AuthZ Models](https://img.shields.io/badge/AuthZ_Models-3-purple)

> A hands-on collection of **8 authentication methods** and **3 authorization models**, each implemented as a standalone Express.js server with full documentation, architecture diagrams, and Medium-style articles. Learn by reading, running, and experimenting.

---

## Overview

This project provides comprehensive examples and documentation for every major authentication and authorization pattern used in modern web development. Each method is implemented as an independent, runnable Express.js server so you can study them in isolation or compare them side by side.

The concepts and implementations are based on ideas from Hayk Simonyan's videos:

- **"7 Authentication Concepts Every Developer Should Know"** -- covering Basic Auth, Bearer Tokens, API Keys, OAuth 2.0, JWT, Refresh Tokens, and SSO.
- **"Authorization Explained: When to Use RBAC, ABAC, ACL & More"** -- covering Role-Based, Attribute-Based, and Access Control List authorization models.

---

## Table of Contents

- [Authentication Methods](#authentication-methods)
- [Authorization Models](#authorization-models)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Documentation](#documentation)
- [Articles](#articles)
- [Authentication vs Authorization](#authentication-vs-authorization)
- [Quick Comparison Tables](#quick-comparison-tables)
- [References](#references)
- [License](#license)

---

## Authentication Methods

| # | Method | Description | Port | Run Command |
|---|--------|-------------|------|-------------|
| 1 | **Basic Authentication** | Username/password Base64 encoded in the `Authorization` header | `3001` | `npm run basic-auth` |
| 2 | **Bearer Tokens** | Opaque token-based authentication sent as a Bearer token | `3002` | `npm run bearer-token` |
| 3 | **API Keys** | Service-to-service authentication using pre-shared keys | `3003` | `npm run api-key` |
| 4 | **OAuth 2.0** | Delegated authentication with Google as the identity provider | `3004` | `npm run oauth2` |
| 5 | **JWT** | JSON Web Token authentication with signed, self-contained tokens | `3005` | `npm run jwt` |
| 6 | **Access & Refresh Tokens** | Dual token pattern with short-lived access and long-lived refresh tokens | `3006` | `npm run refresh-token` |
| 7 | **SSO** | Single Sign-On simulation across multiple services | `3007` | `npm run sso` |
| 8 | **Passkeys (WebAuthn)** | Passwordless auth using public-key cryptography (FIDO2) | `3011` | `npm run passkeys` |

---

## Authorization Models

| # | Model | Description | Port | Run Command |
|---|-------|-------------|------|-------------|
| 1 | **RBAC** | Role-Based Access Control -- permissions derived from assigned roles | `3008` | `npm run rbac` |
| 2 | **ABAC** | Attribute-Based Access Control -- policy decisions based on user, resource, and environment attributes | `3009` | `npm run abac` |
| 3 | **ACL** | Access Control Lists -- per-resource permission entries for individual users or groups | `3010` | `npm run acl` |

---

## Project Structure

```
AuthenticationAndAuthorization/
├── README.md
├── LICENSE
├── package.json
├── package-lock.json
├── medium-session.json
│
├── src/
│   ├── authentication/
│   │   ├── 01-basic-auth/
│   │   │   └── server.js
│   │   ├── 02-bearer-token/
│   │   │   └── server.js
│   │   ├── 03-api-key/
│   │   │   └── server.js
│   │   ├── 04-oauth2/
│   │   │   ├── server.js
│   │   │   └── .env.example
│   │   ├── 05-jwt/
│   │   │   └── server.js
│   │   ├── 06-refresh-token/
│   │   │   └── server.js
│   │   ├── 07-sso/
│   │   │   └── server.js
│   │   └── 08-passkeys/
│   │       ├── server.js
│   │       └── public/
│   │           └── index.html
│   │
│   └── authorization/
│       ├── 01-rbac/
│       │   └── server.js
│       ├── 02-abac/
│       │   └── server.js
│       └── 03-acl/
│           └── server.js
│
├── docs/
│   ├── authentication/
│   │   ├── 01-basic-authentication.md
│   │   ├── 02-bearer-tokens.md
│   │   ├── 03-api-keys.md
│   │   ├── 04-oauth2.md
│   │   ├── 05-jwt.md
│   │   ├── 06-access-refresh-tokens.md
│   │   ├── 07-sso.md
│   │   └── 08-passkeys.md
│   │
│   └── authorization/
│       ├── 01-rbac.md
│       ├── 02-abac.md
│       ├── 03-acl.md
│       ├── 04-delegated-auth-oauth2.md
│       └── 05-token-based-authorization.md
│
├── articles/
│   ├── 01-basic-auth-and-bearer-tokens.md
│   ├── 02-api-keys-demystified.md
│   ├── 03-oauth2-the-complete-guide.md
│   ├── 04-jwt-deep-dive.md
│   ├── 05-access-refresh-tokens.md
│   ├── 06-sso-explained.md
│   ├── 07-rbac-guide.md
│   ├── 08-abac-and-acl.md
│   ├── 09-complete-auth-landscape.md
│   └── 10-passkeys-future-of-auth.md
│
├── diagrams/                          # SVG architecture diagrams
│   ├── 01-basic-auth.svg
│   ├── 02-bearer-token.svg
│   ├── 03-api-key.svg
│   ├── 04-oauth2.svg
│   ├── 05-jwt.svg
│   ├── 06-refresh-token.svg
│   ├── 07-sso.svg
│   ├── 08-passkeys.svg
│   ├── 09-rbac.svg
│   ├── 10-abac.svg
│   ├── 11-acl.svg
│   └── 12-auth-landscape.svg
│
└── medium/                            # Medium article content
    ├── authentication-article.md
    └── authorization-article.md
```

---

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) v18 or higher
- npm (comes with Node.js)

### Installation

```bash
# Clone the repository
git clone https://github.com/vineetpanwar/AuthenticationAndAuthorization.git

# Navigate into the project
cd AuthenticationAndAuthorization

# Install dependencies
npm install
```

### Run Your First Example

```bash
# Start with Basic Auth on port 3001
npm run basic-auth
```

Each server runs independently. Open the indicated port in your browser or use a tool like `curl` or Postman to interact with the endpoints.

> **Note:** The OAuth 2.0 example requires Google credentials. Copy `src/authentication/04-oauth2/.env.example` to `.env` and fill in your `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` before running `npm run oauth2`.

---

## Documentation

### Authentication Docs

| Doc | Path |
|-----|------|
| Basic Authentication | [`docs/authentication/01-basic-authentication.md`](docs/authentication/01-basic-authentication.md) |
| Bearer Tokens | [`docs/authentication/02-bearer-tokens.md`](docs/authentication/02-bearer-tokens.md) |
| API Keys | [`docs/authentication/03-api-keys.md`](docs/authentication/03-api-keys.md) |
| OAuth 2.0 | [`docs/authentication/04-oauth2.md`](docs/authentication/04-oauth2.md) |
| JWT | [`docs/authentication/05-jwt.md`](docs/authentication/05-jwt.md) |
| Access & Refresh Tokens | [`docs/authentication/06-access-refresh-tokens.md`](docs/authentication/06-access-refresh-tokens.md) |
| SSO | [`docs/authentication/07-sso.md`](docs/authentication/07-sso.md) |

### Authorization Docs

| Doc | Path |
|-----|------|
| RBAC | [`docs/authorization/01-rbac.md`](docs/authorization/01-rbac.md) |
| ABAC | [`docs/authorization/02-abac.md`](docs/authorization/02-abac.md) |
| ACL | [`docs/authorization/03-acl.md`](docs/authorization/03-acl.md) |
| Delegated Auth (OAuth 2.0) | [`docs/authorization/04-delegated-auth-oauth2.md`](docs/authorization/04-delegated-auth-oauth2.md) |
| Token-Based Authorization | [`docs/authorization/05-token-based-authorization.md`](docs/authorization/05-token-based-authorization.md) |

---

## Articles

The [`articles/`](articles/) directory is reserved for in-depth write-ups and companion blog posts covering authentication and authorization topics. Contributions are welcome -- see the folder for any published articles.

---

## Authentication vs Authorization

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Client Request                               │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               v
              ┌────────────────────────────────┐
              │     AUTHENTICATION (Auth-N)     │
              │                                 │
              │  "Who are you?"                 │
              │                                 │
              │  - Verify identity              │
              │  - Validate credentials         │
              │  - Issue token / session         │
              └───────────────┬─────────────────┘
                              │
                     Authenticated?
                     /            \
                   No              Yes
                   │                │
                   v                v
             ┌──────────┐  ┌────────────────────────────────┐
             │  401      │  │     AUTHORIZATION (Auth-Z)      │
             │  Denied   │  │                                 │
             └──────────┘  │  "What can you do?"              │
                            │                                 │
                            │  - Check roles (RBAC)           │
                            │  - Evaluate attributes (ABAC)   │
                            │  - Lookup ACL entries (ACL)      │
                            └───────────────┬─────────────────┘
                                            │
                                   Authorized?
                                   /          \
                                 No            Yes
                                 │              │
                                 v              v
                           ┌──────────┐  ┌──────────────┐
                           │  403      │  │  200 OK      │
                           │  Forbidden│  │  Access      │
                           └──────────┘  │  Granted      │
                                          └──────────────┘
```

**In short:**

- **Authentication (Auth-N)** answers: _"Who are you?"_ -- it verifies identity.
- **Authorization (Auth-Z)** answers: _"What are you allowed to do?"_ -- it enforces permissions.

Authentication always comes first. You must know _who_ someone is before you can decide _what_ they can access.

---

## Quick Comparison Tables

### Authentication Methods Comparison

| Method | Stateless | Complexity | Security Level | Best For |
|--------|-----------|------------|----------------|----------|
| **Basic Auth** | Yes | Low | Low (Base64 is not encryption) | Internal tools, development |
| **Bearer Tokens** | Yes | Low | Medium | Simple API access |
| **API Keys** | Yes | Low | Medium | Service-to-service communication |
| **OAuth 2.0** | No | High | High | Third-party integrations, social login |
| **JWT** | Yes | Medium | High | Distributed systems, microservices |
| **Refresh Tokens** | No | Medium | High | Long-lived sessions, mobile apps |
| **SSO** | No | High | High | Enterprise, multi-app ecosystems |

### Authorization Models Comparison

| Model | Granularity | Complexity | Scalability | Best For |
|-------|-------------|------------|-------------|----------|
| **RBAC** | Medium (role-level) | Low | High | Most applications, team-based permissions |
| **ABAC** | High (attribute-level) | High | High | Context-aware policies, regulatory compliance |
| **ACL** | High (per-resource) | Medium | Medium | File systems, document-level permissions |

---

## References

- [7 Authentication Concepts Every Developer Should Know -- Hayk Simonyan (YouTube)](https://www.youtube.com/watch?v=5w1dRfhQSmg)
- [Authorization Explained: When to Use RBAC, ABAC, ACL & More -- Hayk Simonyan (YouTube)](https://www.youtube.com/watch?v=eEA1_GFUBxg)
- [Hayk Simonyan's Substack](https://hayksimonyan.substack.com/)

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Vineet Panwar
