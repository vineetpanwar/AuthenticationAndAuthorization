# Passkeys: The Future of Authentication -- No More Passwords

**Estimated read time: 15 minutes**

---

Passwords are broken. We have known this for years, but we keep using them
because nothing better was ready for mainstream adoption. That has changed.
Passkeys -- backed by Apple, Google, and Microsoft -- are poised to eliminate
passwords entirely. In this article, we will explore what passkeys are, why they
matter, how they work under the hood, and how you can implement them today.

---

## The Password Problem

Think about your average day online. You have passwords for your email, your
bank, social media, shopping sites, work tools, streaming services, and dozens
of other accounts. Security experts tell you each password should be unique,
long, and random. In practice, most people reuse a handful of passwords across
all their accounts.

The consequences are staggering:

- **80% of data breaches** involve compromised credentials (Verizon DBIR)
- **65% of users** reuse passwords across multiple sites
- **Phishing attacks** increased by 61% year-over-year, with credential theft
  as the primary goal
- Companies spend **billions annually** on password-related support, breaches,
  and infrastructure

We have tried to patch the password problem with multi-factor authentication
(MFA), but SMS codes can be intercepted, TOTP codes can be phished through
real-time relay attacks, and push notifications suffer from "MFA fatigue"
attacks where users approve fraudulent requests just to make the prompts stop.

The fundamental issue is that passwords are **shared secrets**. Both you and the
server know the password, which means the server must store it, the network must
transmit it, and you must remember it. Each of these is an attack surface.

What if we could authenticate without sharing any secret at all?

---

## Enter Passkeys

A **passkey** is a cryptographic credential stored on your device. Instead of
typing a password, you verify yourself with a biometric (fingerprint, face scan)
or a device PIN. Behind the scenes, your device uses public-key cryptography to
prove your identity to the server -- without ever sending a secret over the
network.

Here is the key insight: **the server never learns your private key**. It only
stores a public key. Even if attackers breach the server and steal every public
key in the database, those keys are mathematically useless for logging in. There
is no password hash to crack, no secret to brute-force.

### Passkeys in Plain English

Imagine you have a special stamp that only you own. To prove your identity to a
website, the website sends you a random piece of paper. You stamp it and send it
back. The website has a mold of your stamp (but not the stamp itself) and can
verify the imprint matches. Even if someone sees the stamped paper, they cannot
recreate your stamp. And even if someone steals the mold from the website, they
still cannot make the stamp.

That is essentially how passkeys work, with the "stamp" being a cryptographic
private key and the "mold" being the corresponding public key.

---

## The Standards Behind Passkeys

Passkeys are not proprietary. They are built on open standards:

```
+------------------------------------------------------------+
|  "Passkeys" (consumer-facing term)                         |
|                                                            |
|  +------------------------------------------------------+  |
|  |  WebAuthn (W3C Standard)                              |  |
|  |  The browser API: navigator.credentials.create/get    |  |
|  +------------------------------------------------------+  |
|                                                            |
|  +------------------------------------------------------+  |
|  |  CTAP2 (FIDO Alliance)                                |  |
|  |  How the browser talks to authenticators              |  |
|  |  (USB, NFC, Bluetooth, internal)                      |  |
|  +------------------------------------------------------+  |
|                                                            |
|  Together: FIDO2 = WebAuthn + CTAP2                        |
+------------------------------------------------------------+
```

- **WebAuthn** is the W3C standard that defines the JavaScript API browsers
  expose. When your code calls `navigator.credentials.create()` or
  `navigator.credentials.get()`, you are using WebAuthn.

- **CTAP2** (Client to Authenticator Protocol) defines how the browser
  communicates with authenticators -- whether that is the built-in Touch ID
  sensor, a USB security key, or a phone connected via Bluetooth.

- **FIDO2** is the umbrella term for WebAuthn + CTAP2 together.

- **Passkey** is the user-friendly branding for FIDO2 credentials, especially
  the "synced" variety that can roam across your devices via iCloud Keychain,
  Google Password Manager, or a third-party password manager.

---

## How Passkeys Work: Registration

When a user creates an account (or adds a passkey to an existing account), the
**registration ceremony** occurs:

```
  User's Browser              Your Server               Authenticator
       |                          |                       (Touch ID, etc.)
       |                          |                           |
       |  "I want to register"    |                           |
       |------------------------->|                           |
       |                          |                           |
       |  Here's a challenge      |                           |
       |  + configuration         |                           |
       |<-------------------------|                           |
       |                          |                           |
       |  "Please create a        |                           |
       |   credential for this    |                           |
       |   site"                  |                           |
       |-------------------------------------------------->  |
       |                          |                           |
       |                          |    User touches sensor    |
       |                          |    or enters PIN          |
       |                          |                           |
       |                          |    Authenticator creates: |
       |                          |    - Private key (kept)   |
       |                          |    - Public key (returned)|
       |                          |                           |
       |  Here's the public key   |                           |
       |  + proof of creation     |                           |
       |<---------------------------------------------------- |
       |                          |                           |
       |  "Store this public key" |                           |
       |------------------------->|                           |
       |                          |                           |
       |                  Server verifies the proof,          |
       |                  stores the public key                |
       |                          |                           |
       |  "You're registered!"    |                           |
       |<-------------------------|                           |
```

What happens at each step:

1. **Server generates options**: A random challenge (nonce), the relying party
   info (your domain), and the user's info (an opaque ID, not the username).

2. **Browser calls the authenticator**: The browser uses CTAP2 to ask the
   authenticator (e.g., Touch ID) to create a new credential.

3. **User verifies**: The user touches the fingerprint sensor, scans their face,
   or enters a PIN. This proves they are physically present and consenting.

4. **Key pair created**: The authenticator generates an asymmetric key pair. The
   private key is stored in the device's secure enclave. The public key is
   returned to the browser.

5. **Server stores the public key**: The server receives the public key,
   verifies the attestation (proof of creation), and stores it alongside the
   user's account.

The private key **never leaves the device**. The server **never sees it**. This
is the fundamental security property that makes passkeys so powerful.

---

## How Passkeys Work: Authentication

When the user returns to log in, the **authentication ceremony** occurs:

```
  User's Browser              Your Server               Authenticator
       |                          |                           |
       |  "I want to log in"      |                           |
       |------------------------->|                           |
       |                          |                           |
       |  Here's a challenge      |                           |
       |  + your credential IDs   |                           |
       |<-------------------------|                           |
       |                          |                           |
       |  "Please sign this       |                           |
       |   challenge"             |                           |
       |-------------------------------------------------->  |
       |                          |                           |
       |                          |    User touches sensor    |
       |                          |                           |
       |                          |    Authenticator signs    |
       |                          |    the challenge with     |
       |                          |    the private key        |
       |                          |                           |
       |  Here's the signature    |                           |
       |<---------------------------------------------------- |
       |                          |                           |
       |  "Verify this signature" |                           |
       |------------------------->|                           |
       |                          |                           |
       |                  Server verifies signature           |
       |                  using stored public key              |
       |                          |                           |
       |  "Welcome back!"         |                           |
       |<-------------------------|                           |
```

The critical verification:

1. **Challenge matches**: The server checks that the signature is over the
   exact challenge it issued (prevents replay attacks).

2. **Origin matches**: The signature includes the origin (domain). If the user
   were on a phishing site, the origin would not match, and authentication
   would fail. The browser enforces this -- the user cannot override it.

3. **Signature is valid**: The server uses the stored public key to verify the
   signature. Only the holder of the corresponding private key could have
   produced it.

4. **Counter incremented**: The authenticator maintains a counter that
   increments on each use. If the counter goes backward, it may indicate a
   cloned credential.

---

## Why Passkeys Are Phishing-Resistant

This is the single most important security property of passkeys, and it is worth
understanding deeply.

With passwords, phishing works like this:

1. Attacker creates `evil-bank.com` that looks identical to `real-bank.com`
2. User enters their password on `evil-bank.com`
3. Attacker now has the user's password and can log in to `real-bank.com`

With passkeys, this attack is **structurally impossible**:

1. Attacker creates `evil-bank.com`
2. User visits `evil-bank.com`
3. The browser checks: "Does the user have a credential for `evil-bank.com`?"
4. Answer: No. The credential was registered for `real-bank.com`.
5. **The credential does not even appear**. The browser will not offer it.

Even if the attacker somehow triggers a WebAuthn ceremony, the signature will
include `evil-bank.com` as the origin. The real server at `real-bank.com` will
reject it because the origin does not match.

This is not a behavioral protection (like "be careful what you click"). It is a
**cryptographic guarantee** enforced by the browser and the authenticator. The
user does not need to notice anything suspicious. The protocol itself prevents
the attack.

```
  Traditional Phishing:

  User ---[password]--> evil-bank.com ---[password]--> real-bank.com
                         (steals it)                   (attacker logs in)

  With Passkeys:

  User ---[nothing]--> evil-bank.com
                        (no credential exists for this domain)
                        ATTACK BLOCKED BY PROTOCOL
```

---

## Synced Passkeys: Solving the Lost Device Problem

Early FIDO2 implementations had a significant drawback: if you lost your device,
you lost your credentials. This was fine for security-conscious users with
backup keys but terrible for mainstream adoption.

**Synced passkeys** solve this. Your credentials are encrypted and synced across
your devices through cloud services:

- **Apple iCloud Keychain**: Syncs passkeys across all your Apple devices
- **Google Password Manager**: Syncs passkeys across Android and Chrome
- **Third-party managers**: 1Password, Dashlane, Bitwarden can store and sync
  passkeys across all platforms

When you create a passkey on your iPhone, it immediately becomes available on
your Mac, iPad, and even on a Windows PC through a cross-device flow (scanning
a QR code with your phone).

This is a pragmatic trade-off. Synced passkeys are slightly less secure than
device-bound credentials (since the encrypted credentials exist in the cloud),
but they are **dramatically more secure than passwords** and practical enough
for billions of users.

---

## Real-World Adoption

Passkeys are not theoretical. They are deployed at scale:

**Platform Support (Built-in):**
- **Apple**: iOS 16+, macOS Ventura+, Safari 16+ (since September 2022)
- **Google**: Android 9+, Chrome 108+ (since late 2022)
- **Microsoft**: Windows 10/11 with Windows Hello, Edge (since 2023)

**Major Websites and Services:**
- **Google**: Passkeys as default sign-in method for all Google accounts
- **Apple**: Passkey sign-in for Apple ID
- **GitHub**: Passkey support for all developer accounts
- **PayPal**: Passkey login on iOS and Android
- **Amazon**: Passkey support for all customer accounts
- **WhatsApp**: Passkey-based account verification
- **Shopify**: Passkey login for merchants
- **Best Buy, Kayak, TikTok**: Consumer-facing passkey support
- **1Password, Dashlane, Bitwarden**: Both passkey storage and passkey login

**Industry Momentum:**
- The FIDO Alliance reports over 13 billion accounts can use passkeys
- Google reports that passkey sign-ins are 4x faster than passwords
- Microsoft reports a 99.9% reduction in account compromise for passkey users

---

## Implementing Passkeys: A Code Walkthrough

Let us look at the key parts of a server-side passkey implementation using
Node.js and the `@simplewebauthn/server` library.

### Server Setup

```javascript
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

// Relying Party configuration
const rpName = 'My Application';
const rpID = 'localhost';               // Your domain in production
const origin = 'http://localhost:3011'; // Must match the browser's origin
```

### Registration: Generating Options

```javascript
app.post('/api/register/options', async (req, res) => {
  const { username } = req.body;

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: user.id,           // Opaque user handle (NOT the username)
    userName: username,
    attestationType: 'none',   // 'none' is simplest; 'direct' for enterprise
    supportedAlgorithmIDs: [-7, -257], // ES256, RS256
  });

  // Store the challenge for verification (single-use!)
  challengeStore.set(username, options.challenge);

  return res.json(options);
});
```

### Registration: Verifying the Response

```javascript
app.post('/api/register/verify', async (req, res) => {
  const { username, attestationResponse } = req.body;

  const verification = await verifyRegistrationResponse({
    response: attestationResponse,
    expectedChallenge: challengeStore.get(username),
    expectedOrigin: origin,
    expectedRPID: rpID,
  });

  if (verification.verified) {
    // Store the credential (public key, credential ID, counter)
    const { credential } = verification.registrationInfo;
    user.credentials.push({
      id: credential.id,
      publicKey: credential.publicKey,
      counter: credential.counter,
    });
  }
});
```

### Authentication: Generating Options

```javascript
app.post('/api/login/options', async (req, res) => {
  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials: user.credentials.map((cred) => ({
      id: cred.id,
      transports: cred.transports,
    })),
    userVerification: 'preferred',
  });

  challengeStore.set(username, options.challenge);
  return res.json(options);
});
```

### Authentication: Verifying the Signature

```javascript
app.post('/api/login/verify', async (req, res) => {
  const verification = await verifyAuthenticationResponse({
    response: assertionResponse,
    expectedChallenge: challengeStore.get(username),
    expectedOrigin: origin,
    expectedRPID: rpID,
    credential: {
      id: matchingCredential.id,
      publicKey: matchingCredential.publicKey,
      counter: matchingCredential.counter,
    },
  });

  if (verification.verified) {
    // Update the counter (for clone detection)
    matchingCredential.counter = verification.authenticationInfo.newCounter;
    // User is authenticated!
  }
});
```

### Client Side: Using the Browser API

```javascript
// Registration: calls navigator.credentials.create() under the hood
const attestationResponse = await SimpleWebAuthnBrowser.startRegistration({
  optionsJSON: options,
});

// Authentication: calls navigator.credentials.get() under the hood
const assertionResponse = await SimpleWebAuthnBrowser.startAuthentication({
  optionsJSON: options,
});
```

The `@simplewebauthn/browser` library handles the encoding/decoding between the
server's JSON format and the browser's `ArrayBuffer`-based WebAuthn API.

---

## Security Comparison: Passkeys vs Everything Else

```
                    Phishing   Server     Replay    User      MFA
                    Resistant  Breach     Proof     Friction  Built-in
                    ---------  ---------  --------  --------  --------
Passwords              No      High risk    No       Medium     No
Passwords + SMS MFA    Weak    High risk    Weak     High       Yes
Passwords + TOTP       Weak    High risk    Weak     High       Yes
Passwords + Push       Weak    High risk    Medium   Medium     Yes
Magic Links            Medium  Low risk     Medium   Medium     No
Passkeys               YES     NO RISK      YES      LOW        YES
```

Passkeys are the first authentication method that scores well on every axis
simultaneously. They are phishing-resistant, breach-resistant, replay-proof,
low-friction, and multi-factor in a single step.

---

## Addressing Common Concerns

### "What if I lose my device?"

With synced passkeys, your credentials are backed up to the cloud (iCloud,
Google, 1Password). Getting a new device and signing into your cloud account
restores all your passkeys. For device-bound credentials (like security keys),
you should register multiple authenticators as backup.

### "What about shared or public computers?"

You can use the **hybrid flow**: scan a QR code on the shared computer with your
phone. Your phone acts as the authenticator over Bluetooth. The credential never
touches the shared computer.

### "Is the biometric sent to the server?"

Absolutely not. The biometric (fingerprint, face) is only used locally to unlock
the private key on your device. The server never receives, processes, or stores
any biometric data.

### "What about browser support?"

WebAuthn is supported in all major browsers: Chrome, Firefox, Safari, and Edge.
On mobile, both iOS Safari and Android Chrome have full support. For the small
percentage of users on older browsers, you can offer password fallback.

### "Can passkeys be exported or moved?"

Synced passkeys can be moved between ecosystems (e.g., from iCloud to Google)
through emerging export/import standards. Device-bound credentials on hardware
security keys cannot be extracted by design -- this is a security feature.

---

## Key Takeaways

1. **Passkeys replace passwords** with public-key cryptography. No shared
   secrets, no password databases to breach.

2. **Phishing is structurally impossible** with passkeys. The browser
   cryptographically binds credentials to the domain.

3. **User experience is better** than passwords. A fingerprint scan is faster
   and easier than typing a password + MFA code.

4. **Synced passkeys** solve the device-loss problem by backing up credentials
   through iCloud, Google, or third-party password managers.

5. **Major platforms support passkeys today**: Apple, Google, Microsoft, and
   most major browsers.

6. **Adoption is accelerating**: Google, GitHub, Amazon, PayPal, and many
   others already support passkeys.

7. **Implementation is straightforward** using libraries like
   `@simplewebauthn/server` and `@simplewebauthn/browser`.

8. **Passkeys are multi-factor by default**: possession of the device
   (something you have) plus biometric or PIN (something you are/know).

---

## What's Next?

### For Users

- **Try it now**: Go to your Google account settings and set up a passkey. Try
  it on GitHub, Amazon, or any site that supports them. Experience how much
  smoother it is than a password.

- **Use a password manager with passkey support**: 1Password, Dashlane, and
  Bitwarden all support storing passkeys and syncing them across platforms.

### For Developers

- **Add passkey support alongside passwords**: You do not need to remove
  password login. Offer passkeys as an option and let users experience the
  difference.

- **Use established libraries**: `@simplewebauthn/server` (Node.js),
  `py_webauthn` (Python), `webauthn-rs` (Rust), `java-webauthn-server` (Java)
  handle the cryptographic heavy lifting.

- **Plan for progressive adoption**:
  1. Offer passkeys as an alternative login method
  2. Prompt users to create a passkey after password login
  3. Default new accounts to passkey-first
  4. Eventually allow users to remove their passwords entirely

- **Think about account recovery**: Design flows for when users lose all their
  authenticators. Options include email-based recovery, recovery codes, or
  identity verification.

### For the Industry

The FIDO Alliance and W3C continue to evolve the standards. Upcoming work
includes:

- **Credential exchange protocols** for moving passkeys between ecosystems
- **Attestation improvements** for enterprise trust models
- **Conditional UI** (autofill integration) to make passkey discovery seamless
- **Signals API** for relying parties to communicate credential state to
  providers

The trajectory is clear. Passwords have been the default for decades, but
passkeys are better in every measurable way: more secure, more usable, and
finally supported by the entire platform ecosystem.

The question is not whether passkeys will replace passwords. It is how quickly.

---

*This article is part of the Authentication and Authorization series. Check out
the companion demo at `src/authentication/08-passkeys/` to see a working
implementation you can run locally.*
