# Passkeys (WebAuthn / FIDO2) Authentication

## Table of Contents

1. [What Are Passkeys?](#what-are-passkeys)
2. [The Problem Passkeys Solve](#the-problem-passkeys-solve)
3. [How It Works](#how-it-works)
4. [Registration Ceremony](#registration-ceremony)
5. [Authentication Ceremony](#authentication-ceremony)
6. [Public Key Cryptography Basics](#public-key-cryptography-basics)
7. [Key Pair Architecture](#key-pair-architecture)
8. [Types of Authenticators](#types-of-authenticators)
9. [Synced Passkeys vs Device-Bound Passkeys](#synced-passkeys-vs-device-bound-passkeys)
10. [Security Considerations](#security-considerations)
11. [Pros and Cons](#pros-and-cons)
12. [Real-World Adoption](#real-world-adoption)
13. [Comparison with Other Auth Methods](#comparison-with-other-auth-methods)
14. [When to Use Passkeys](#when-to-use-passkeys)
15. [Running the Demo](#running-the-demo)

---

## What Are Passkeys?

**Passkeys** are a modern, passwordless authentication mechanism built on the
**WebAuthn** (Web Authentication) standard, which is part of the **FIDO2** framework
developed by the FIDO Alliance and W3C.

Instead of sharing a secret (password) between user and server, passkeys use
**public-key cryptography**. The user's device generates a unique key pair:
- The **private key** stays on the device, secured by biometrics or a PIN
- The **public key** is sent to the server

Authentication works by proving you hold the private key without ever revealing
it. This is fundamentally different from passwords, where the secret itself is
transmitted and stored.

### The Standards Stack

```
+------------------------------------------------------+
|  Passkeys (User-facing concept / branding)           |
+------------------------------------------------------+
|  WebAuthn (W3C Standard - Browser API)               |
|  navigator.credentials.create() / .get()             |
+------------------------------------------------------+
|  CTAP2 (FIDO Alliance - Authenticator Protocol)      |
|  Client to Authenticator Protocol                    |
+------------------------------------------------------+
|  FIDO2 = WebAuthn + CTAP2                            |
+------------------------------------------------------+
```

- **FIDO2**: The umbrella framework encompassing both WebAuthn and CTAP2
- **WebAuthn**: The browser-facing JavaScript API standard (W3C)
- **CTAP2**: The protocol for communication between the browser and the
  authenticator device (USB, NFC, Bluetooth, internal)
- **Passkeys**: The consumer-friendly name for FIDO2/WebAuthn credentials,
  especially synced (multi-device) credentials

---

## The Problem Passkeys Solve

Passwords are the weakest link in most security systems:

| Problem | Description |
|---------|-------------|
| **Phishing** | Users are tricked into entering passwords on fake sites. Passkeys are bound to the domain, so they cannot be phished. |
| **Password reuse** | Users reuse passwords across sites. A breach on one site compromises others. Passkeys are unique per site by design. |
| **Credential stuffing** | Attackers use leaked username/password combos. Passkeys have no shared secret to leak. |
| **Brute force attacks** | Attackers guess passwords. Passkeys use cryptographic keys that cannot be guessed. |
| **Server-side breaches** | Password databases get stolen. The server only stores public keys, which are useless to attackers. |
| **Man-in-the-middle** | Attackers intercept passwords in transit. Passkeys never transmit the private key. |
| **User friction** | Users forget passwords, need resets, get locked out. Passkeys use biometrics - nothing to remember. |

---

## How It Works

Passkeys involve two ceremonies: **Registration** (creating a credential) and
**Authentication** (using a credential to log in).

There are three parties involved:
- **Relying Party (RP)**: Your website/server
- **Client/Browser**: The user's browser that mediates the process
- **Authenticator**: The device/software that holds the private key
  (Touch ID, Windows Hello, YubiKey, phone)

---

## Registration Ceremony

The registration ceremony creates a new credential (key pair) and stores the
public key on the server.

```
 Browser/Client              Relying Party (Server)          Authenticator
      |                              |                            |
      |  1. POST /register/options   |                            |
      |  (username)                  |                            |
      |----------------------------->|                            |
      |                              |                            |
      |  2. Registration Options     |                            |
      |  (challenge, rpID, userID,   |                            |
      |   supported algorithms)      |                            |
      |<-----------------------------|                            |
      |                                                           |
      |  3. navigator.credentials.create(options)                 |
      |  Browser sends options to authenticator via CTAP2         |
      |--------------------------------------------------------->|
      |                                                           |
      |                                 4. User verifies identity |
      |                                 (biometric, PIN, etc.)    |
      |                                                           |
      |                                 5. Authenticator creates  |
      |                                 key pair:                 |
      |                                  - Private key (stored    |
      |                                    securely on device)    |
      |                                  - Public key (returned)  |
      |                                                           |
      |  6. Attestation Response                                  |
      |  (public key, credential ID, attestation, client data)    |
      |<---------------------------------------------------------|
      |                              |                            |
      |  7. POST /register/verify    |                            |
      |  (attestation response)      |                            |
      |----------------------------->|                            |
      |                              |                            |
      |                    8. Server verifies:                    |
      |                    - Challenge matches                    |
      |                    - Origin matches                       |
      |                    - RP ID hash matches                   |
      |                    - Attestation valid                    |
      |                    - Stores public key                    |
      |                              |                            |
      |  9. Success!                 |                            |
      |<-----------------------------|                            |
      |                              |                            |
```

### Registration Data Flow

- **Challenge**: A random value generated by the server (prevents replay attacks)
- **rpID**: The domain of the relying party (e.g., "example.com")
- **userID**: An opaque user handle (NOT the username - to protect privacy)
- **Credential ID**: A unique identifier for the created credential
- **Public Key**: The public half of the key pair, stored by the server
- **Attestation**: Optional proof of the authenticator's make and model

---

## Authentication Ceremony

The authentication ceremony proves the user possesses the private key for a
registered credential.

```
 Browser/Client              Relying Party (Server)          Authenticator
      |                              |                            |
      |  1. POST /login/options      |                            |
      |  (username)                  |                            |
      |----------------------------->|                            |
      |                              |                            |
      |  2. Authentication Options   |                            |
      |  (challenge, rpID,           |                            |
      |   allowed credential IDs)    |                            |
      |<-----------------------------|                            |
      |                                                           |
      |  3. navigator.credentials.get(options)                    |
      |  Browser sends to authenticator via CTAP2                 |
      |--------------------------------------------------------->|
      |                                                           |
      |                                 4. User verifies identity |
      |                                 (biometric, PIN, etc.)    |
      |                                                           |
      |                                 5. Authenticator signs    |
      |                                 the challenge with the    |
      |                                 private key               |
      |                                                           |
      |  6. Assertion Response                                    |
      |  (credential ID, signature, authenticator data,           |
      |   client data hash)                                       |
      |<---------------------------------------------------------|
      |                              |                            |
      |  7. POST /login/verify       |                            |
      |  (assertion response)        |                            |
      |----------------------------->|                            |
      |                              |                            |
      |                    8. Server verifies:                    |
      |                    - Challenge matches                    |
      |                    - Origin / RP ID match                 |
      |                    - Signature valid (using               |
      |                      stored public key)                   |
      |                    - Counter incremented                  |
      |                              |                            |
      |  9. Authenticated!           |                            |
      |<-----------------------------|                            |
      |                              |                            |
```

### What Makes This Phishing-Resistant?

The browser automatically binds the credential to the **origin** (domain). When
the authenticator signs the challenge, the signature includes the origin. If a
user is on `evil-bank.com` instead of `real-bank.com`, the credential for
`real-bank.com` simply will not be available. The browser enforces this at the
API level -- no user action can override it.

---

## Public Key Cryptography Basics

Passkeys rely on **asymmetric cryptography** (public-key cryptography):

```
  +------------------+          +------------------+
  |   Private Key    |          |    Public Key     |
  |  (on device)     |          |  (on server)      |
  +--------+---------+          +--------+---------+
           |                             |
           |   Signs data                |   Verifies signatures
           |   (proves identity)         |   (confirms identity)
           |                             |
           |   NEVER leaves              |   Safe to share
           |   the device                |   publicly
           |                             |
           +-------- KEY PAIR -----------+
                  (mathematically
                    linked)
```

**How signing works:**

1. The server sends a random **challenge** (a nonce)
2. The authenticator **signs** the challenge with the private key
3. The server **verifies** the signature using the public key
4. Only the holder of the private key could have produced that signature

**Algorithms commonly used:**
- **ES256** (ECDSA with P-256): The most common, efficient, and widely supported
- **RS256** (RSASSA-PKCS1-v1_5): Fallback for older authenticators

The critical insight: even if an attacker intercepts the signature, they cannot
extract the private key from it. Each signature is unique to the challenge, so
replaying it is useless (the challenge will have changed).

---

## Key Pair Architecture

```
  +-------------------------------+      +------------------------------+
  |        USER'S DEVICE          |      |         SERVER               |
  |                               |      |                              |
  |  +-------------------------+  |      |  +------------------------+  |
  |  | Authenticator (Secure)  |  |      |  | User Account Database  |  |
  |  |                         |  |      |  |                        |  |
  |  |  Private Key A (site1)  |  |      |  |  User: alice           |  |
  |  |  Private Key B (site2)  |  |      |  |  Public Key A          |  |
  |  |  Private Key C (site3)  |  |      |  |  Credential ID A       |  |
  |  |                         |  |      |  |  Counter: 42           |  |
  |  |  Protected by:          |  |      |  |                        |  |
  |  |  - Biometric (Touch ID) |  |      |  +------------------------+  |
  |  |  - Device PIN           |  |      |                              |
  |  |  - Security enclave     |  |      |  Even if this database is   |
  |  +-------------------------+  |      |  breached, attackers only    |
  |                               |      |  get PUBLIC keys, which      |
  +-------------------------------+      |  are useless for login.      |
                                         +------------------------------+
```

Each credential is **scoped to a specific relying party** (domain). The private
key for `example.com` cannot be used on `another-site.com`. This is enforced
by the browser and authenticator, making phishing structurally impossible.

---

## Types of Authenticators

### Platform Authenticators (Built-in)

These are built into the device the user is using:

| Authenticator | Platform | Verification |
|---------------|----------|-------------|
| Touch ID | macOS, iOS | Fingerprint |
| Face ID | iOS, iPadOS | Face recognition |
| Windows Hello | Windows | Fingerprint, face, or PIN |
| Android Biometric | Android | Fingerprint or face |
| ChromeOS | Chrome OS | Fingerprint or PIN |

**Advantages:** No extra hardware needed, fast, familiar to users.

### Cross-Platform / Roaming Authenticators (External)

These are separate devices that can be used across multiple computers:

| Authenticator | Connection | Type |
|---------------|------------|------|
| YubiKey | USB, NFC | Hardware security key |
| Google Titan | USB, NFC, Bluetooth | Hardware security key |
| Phone as authenticator | Bluetooth/QR code | Hybrid flow |
| Feitian keys | USB, NFC | Hardware security key |

**Advantages:** Can be used on any computer, portable, works on shared machines.

### Hybrid Flow (Phone as Authenticator)

A phone can act as an authenticator for a login on a different device:

1. User starts login on laptop
2. Browser shows a QR code
3. User scans QR code with their phone
4. Phone prompts for biometric verification
5. Phone communicates with laptop via Bluetooth
6. Laptop completes the login

This bridges the gap between platform and cross-platform authenticators.

---

## Synced Passkeys vs Device-Bound Passkeys

### Synced Passkeys (Multi-Device Credentials)

Modern passkeys can be **synced across devices** through cloud services:

- **Apple**: iCloud Keychain (syncs across iPhone, iPad, Mac)
- **Google**: Google Password Manager (syncs across Android, Chrome)
- **Microsoft**: Microsoft Account (syncs across Windows devices)
- **Third-party**: 1Password, Dashlane, Bitwarden (cross-platform sync)

**Pros:** Survive device loss, work across multiple devices, no backup headaches
**Cons:** Cloud provider has access to encrypted credentials, slightly weaker
security model than device-bound

### Device-Bound Passkeys

These stay on a single device and cannot be extracted:

- **Hardware security keys** (YubiKey, Titan Key)
- **TPM-bound** credentials on some enterprise configurations

**Pros:** Highest security, no cloud dependency, tamper-resistant
**Cons:** Lost device = lost access (need backup/recovery plan)

---

## Security Considerations

### Strengths

1. **Phishing-resistant**: Credentials are bound to the origin (domain). Cannot
   be used on a different domain, period.

2. **No shared secrets**: The server never receives or stores the private key.
   A server breach exposes only public keys, which are useless for authentication.

3. **Replay-proof**: Each authentication uses a unique challenge. A captured
   response cannot be replayed.

4. **Two-factor in one**: Passkeys combine "something you have" (the device)
   with "something you are" (biometric) or "something you know" (PIN).

5. **Clone detection**: The signature counter increments on each use. If it
   goes backwards or stays the same, the server can detect a cloned credential.

### Concerns and Mitigations

| Concern | Mitigation |
|---------|------------|
| Device loss | Synced passkeys survive device loss; register multiple authenticators; have a recovery flow |
| Account recovery | Provide fallback methods (email link, recovery codes) for when all authenticators are lost |
| Shared devices | Passkeys on shared devices should require user verification (biometric/PIN) |
| Privacy | User handles are opaque (not usernames); attestation can be anonymized |
| Browser support | Supported in all major browsers since 2023; provide fallback for older browsers |
| User education | Users need to understand what passkeys are; clear UI/UX is essential |

---

## Pros and Cons

### Pros

- **Unphishable**: Cryptographically bound to the domain
- **Nothing to remember**: No passwords, no OTP codes
- **Nothing to leak**: Server stores only public keys
- **Fast**: Biometric verification takes a second
- **Multi-factor in one step**: Possession + biometric/PIN
- **Cross-device**: Synced passkeys work on all your devices
- **Standardized**: W3C standard, supported by all major browsers and platforms
- **No password database**: Eliminates the #1 target for attackers

### Cons

- **Adoption is ongoing**: Not all websites support passkeys yet
- **User education**: Concept is new to many users
- **Recovery complexity**: Need to plan for lost devices / authenticators
- **Platform dependency**: Synced passkeys rely on cloud ecosystems
- **Enterprise complexity**: Deploying across organizations requires MDM policies
- **Legacy systems**: Older systems may not support WebAuthn
- **Authenticator availability**: Some devices lack biometric hardware

---

## Real-World Adoption

Passkeys have seen rapid adoption since 2022:

| Company | Implementation |
|---------|----------------|
| **Apple** | Built into iOS 16+, macOS Ventura+; synced via iCloud Keychain |
| **Google** | Default sign-in for Google accounts; synced via Google Password Manager |
| **Microsoft** | Windows Hello integration; Microsoft account support |
| **GitHub** | Passkey support for all accounts since 2023 |
| **PayPal** | Passkey login on iOS and Android |
| **Amazon** | Passkey support for Amazon accounts |
| **WhatsApp** | Passkey support for account verification |
| **Shopify** | Passkey support for merchant accounts |
| **Kayak** | Passkey login for travel bookings |
| **Best Buy** | Passkey support for customer accounts |
| **1Password** | Both a passkey provider (stores passkeys) and supports passkey login |
| **Dashlane** | Passkey support and storage |
| **Bitwarden** | Passkey storage and authentication |

The FIDO Alliance reports that as of 2024, over 13 billion accounts can use
passkeys, and adoption is accelerating.

---

## Comparison with Other Auth Methods

| Feature | Passwords | Passwords + MFA | Passkeys |
|---------|-----------|-----------------|----------|
| Phishing resistance | None | Partial (SMS/TOTP can be phished) | Full |
| Server breach risk | High (password hashes) | High (password hashes) | None (only public keys) |
| User friction | Medium (remember passwords) | High (extra step) | Low (biometric) |
| Replay attacks | Possible | Harder | Impossible |
| Credential stuffing | Possible | Harder | Impossible |
| MFA included | No | Yes (separate step) | Yes (built-in) |
| Nothing to remember | No | No (password + device) | Yes |
| Standardized | No | Partially | Yes (W3C/FIDO2) |
| Recovery | Password reset | Password reset + MFA reset | Recovery flow needed |
| Browser support | Universal | Universal | All modern browsers |

---

## When to Use Passkeys

### Ideal Use Cases

- **Consumer-facing applications**: Banking, e-commerce, social media
- **High-security applications**: Healthcare, government, financial services
- **Enterprise SSO**: Replace password + MFA with a single passkey
- **Progressive enhancement**: Offer passkeys alongside passwords, let users upgrade

### Considerations Before Implementing

1. **Have a fallback**: Not all users can use passkeys yet; support passwords too
2. **Plan for recovery**: Design account recovery for lost authenticators
3. **Test across platforms**: Test on iOS, Android, Windows, macOS, Linux
4. **Educate users**: Provide clear UI explaining what passkeys are
5. **Start optional**: Let users opt-in before making passkeys the default

### Recommended Approach: Progressive Adoption

```
Phase 1: Offer passkeys as an alternative to passwords
Phase 2: Prompt users to create a passkey after password login
Phase 3: Default new accounts to passkeys (with password fallback)
Phase 4: Allow password removal for passkey-only accounts
```

---

## Running the Demo

### Prerequisites

```bash
npm install
```

### Start the Server

```bash
npm run passkeys
# or
node src/authentication/08-passkeys/server.js
```

### Open in Browser

Navigate to `http://localhost:3011`

### Test the Flow

1. **Register**: Enter a username and click "Register". Your browser will prompt
   you to use Touch ID, Windows Hello, or a security key to create a passkey.

2. **Login**: Enter the same username and click "Login". Your browser will prompt
   you to verify with the same authenticator. The server verifies the signature
   and logs you in.

3. **Check the console**: The server logs detailed information about each step.

### Important Notes

- WebAuthn requires either `localhost` or `HTTPS`. It will not work on plain
  HTTP with a non-localhost domain.
- The demo uses in-memory storage. All data is lost when the server restarts.
- Different browsers may present different UI for the authenticator prompt.

---

## Key Terminology

| Term | Definition |
|------|-----------|
| **Relying Party (RP)** | The website/server requesting authentication |
| **Authenticator** | Device/software that creates and stores credentials (Touch ID, YubiKey) |
| **Credential** | The public key + metadata stored on the server |
| **Challenge** | A random value sent by the server to prevent replay attacks |
| **Attestation** | Proof of the authenticator's make/model (optional) |
| **Assertion** | Proof the user possesses the private key (signed challenge) |
| **User Handle** | An opaque user identifier sent to the authenticator (not the username) |
| **User Verification (UV)** | Biometric or PIN check on the authenticator |
| **Ceremony** | The complete registration or authentication flow |
| **CTAP2** | Client to Authenticator Protocol (how browser talks to authenticator) |

---

## Further Reading

- [WebAuthn Specification (W3C)](https://www.w3.org/TR/webauthn-3/)
- [FIDO Alliance](https://fidoalliance.org/)
- [passkeys.dev](https://passkeys.dev/) - Developer resources
- [SimpleWebAuthn Documentation](https://simplewebauthn.dev/)
- [Can I Use: WebAuthn](https://caniuse.com/webauthn)
