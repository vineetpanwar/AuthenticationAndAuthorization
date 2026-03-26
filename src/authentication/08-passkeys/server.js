/**
 * ============================================================================
 * Passkeys (WebAuthn / FIDO2) Authentication Server
 * ============================================================================
 *
 * This server demonstrates the complete WebAuthn/Passkey flow:
 *
 *   1. REGISTRATION (also called "attestation ceremony"):
 *      - Server generates a challenge and registration options
 *      - Browser prompts user to create a credential (biometric/PIN/security key)
 *      - Authenticator creates a public-private key pair
 *      - Server receives and verifies the public key + attestation
 *      - Server stores the public key credential for future logins
 *
 *   2. AUTHENTICATION (also called "assertion ceremony"):
 *      - Server generates a challenge and authentication options
 *      - Browser prompts user to use their credential (biometric/PIN/security key)
 *      - Authenticator signs the challenge with the private key
 *      - Server verifies the signature using the stored public key
 *      - User is authenticated without ever sending a password
 *
 * Key Concepts:
 *   - Relying Party (RP): The server/website requesting authentication (us)
 *   - Authenticator: The device/software that holds the private key
 *     (e.g., Touch ID, Windows Hello, YubiKey)
 *   - Challenge: A random value to prevent replay attacks
 *   - Credential: The public key + metadata stored on the server
 *
 * Port: 3011
 * ============================================================================
 */

const express = require('express');
const path = require('path');
const crypto = require('crypto');

// -------------------------------------------------------------------
// SimpleWebAuthn server library handles the cryptographic operations
// for generating options and verifying responses.
// -------------------------------------------------------------------
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const PORT = 3011;

// -------------------------------------------------------------------
// Middleware
// -------------------------------------------------------------------
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// -------------------------------------------------------------------
// Relying Party (RP) Configuration
// -------------------------------------------------------------------
// The RP represents this server/application. The rpID must match the
// domain the user visits. For local development, "localhost" works.
// In production, this would be your actual domain (e.g., "example.com").
// -------------------------------------------------------------------
const rpName = 'Auth Demo - Passkeys';
const rpID = 'localhost';
const origin = `http://localhost:${PORT}`;

// -------------------------------------------------------------------
// In-Memory Data Stores
// -------------------------------------------------------------------
// In production, these would be backed by a real database.
//
// userStore: Maps username -> user object with credentials
//   {
//     id: Uint8Array (user handle, opaque to the authenticator),
//     username: string,
//     credentials: [
//       {
//         id: string (base64url credential ID),
//         publicKey: Uint8Array,
//         counter: number (signature counter for clone detection),
//         transports: string[] (how the authenticator communicates)
//       }
//     ]
//   }
//
// challengeStore: Maps username -> current challenge (base64url string)
//   Challenges are single-use and time-limited in production.
// -------------------------------------------------------------------
const userStore = new Map();
const challengeStore = new Map();

/**
 * Helper: Generate a random user ID (user handle).
 * The user handle is an opaque identifier for the user. It should NOT
 * be the username or email - it exists so the authenticator can identify
 * the user without revealing PII if the authenticator is inspected.
 */
function generateUserID() {
  return crypto.randomBytes(32);
}

// =====================================================================
// REGISTRATION FLOW
// =====================================================================

/**
 * Step 1 of Registration: Generate registration options.
 *
 * The client calls this endpoint to get the parameters needed to create
 * a new credential. The server generates:
 *   - A random challenge (to prevent replay attacks)
 *   - RP information (name, ID)
 *   - User information (ID, name, display name)
 *   - Supported algorithms (ES256, RS256)
 *   - Excludes any credentials the user already registered (to prevent
 *     re-registration of the same authenticator)
 */
app.post('/api/register/options', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username || typeof username !== 'string' || username.trim() === '') {
      return res.status(400).json({ error: 'Username is required' });
    }

    console.log(`\n--- REGISTRATION: Generating options for "${username}" ---`);

    // Look up existing user or create a new one
    let user = userStore.get(username);
    if (!user) {
      // New user: create an entry with a random user handle
      const userID = generateUserID();
      user = {
        id: userID,
        username,
        credentials: [],
      };
      userStore.set(username, user);
      console.log(`  Created new user record for "${username}"`);
    } else {
      console.log(`  Found existing user "${username}" with ${user.credentials.length} credential(s)`);
    }

    // Generate registration options using SimpleWebAuthn
    // This creates the PublicKeyCredentialCreationOptions that the browser needs
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      // userID must be a Uint8Array - it's the "user handle" sent to the authenticator
      userID: user.id,
      userName: username,
      userDisplayName: username,

      // Timeout in milliseconds - how long the user has to complete the ceremony
      timeout: 60000,

      // Attestation type:
      //   'none'     - Don't request attestation (simplest, most privacy-preserving)
      //   'direct'   - Request attestation from the authenticator
      //   'indirect' - Allow the client to anonymize attestation
      // For most apps, 'none' is sufficient. Attestation lets you verify the
      // make/model of the authenticator, which is mainly useful for enterprise.
      attestationType: 'none',

      // Prevent re-registration of authenticators the user already registered
      excludeCredentials: user.credentials.map((cred) => ({
        id: cred.id,
        // Transports hint helps the browser find the right authenticator
        transports: cred.transports,
      })),

      // Which authenticator types to allow:
      //   'platform'       - Built-in (Touch ID, Windows Hello, Face ID)
      //   'cross-platform' - External (YubiKey, phone as authenticator)
      // Omitting this allows both types.
      // authenticatorSelection: {
      //   authenticatorAttachment: 'platform',
      // },

      // Supported public key algorithms (COSE algorithm identifiers):
      //   -7  = ES256 (ECDSA with P-256 and SHA-256) - preferred, most widely supported
      //   -257 = RS256 (RSASSA-PKCS1-v1_5 with SHA-256) - fallback for older authenticators
      supportedAlgorithmIDs: [-7, -257],
    });

    // Store the challenge so we can verify it in the next step.
    // The challenge is single-use: once verified, it must be discarded.
    challengeStore.set(username, options.challenge);

    console.log('  Registration options generated successfully');
    console.log(`  Challenge: ${options.challenge.substring(0, 20)}...`);
    console.log(`  RP ID: ${rpID}`);
    console.log(`  Supported algorithms: ES256 (-7), RS256 (-257)`);

    return res.json(options);
  } catch (error) {
    console.error('  Error generating registration options:', error);
    return res.status(500).json({ error: 'Failed to generate registration options' });
  }
});

/**
 * Step 2 of Registration: Verify the registration response.
 *
 * After the browser/authenticator creates a credential, the client sends
 * the attestation response back here. The server verifies:
 *   - The challenge matches what was issued
 *   - The origin matches (prevents phishing on wrong domain)
 *   - The RP ID hash matches
 *   - The attestation is valid (if requested)
 *   - The public key algorithm is supported
 *
 * If everything checks out, the server stores the new credential.
 */
app.post('/api/register/verify', async (req, res) => {
  try {
    const { username, attestationResponse } = req.body;

    if (!username || !attestationResponse) {
      return res.status(400).json({ error: 'Username and attestation response are required' });
    }

    console.log(`\n--- REGISTRATION: Verifying response for "${username}" ---`);

    // Retrieve the challenge we stored in step 1
    const expectedChallenge = challengeStore.get(username);
    if (!expectedChallenge) {
      console.log('  ERROR: No challenge found - registration options were not generated first');
      return res.status(400).json({ error: 'No challenge found. Call /api/register/options first.' });
    }

    const user = userStore.get(username);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    // Verify the attestation response using SimpleWebAuthn
    // This performs all the cryptographic verification steps
    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    console.log(`  Verification result: ${verification.verified ? 'SUCCESS' : 'FAILED'}`);

    if (verification.verified && verification.registrationInfo) {
      const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

      // Store the credential for future authentication
      // The critical pieces are:
      //   - id: identifies this specific credential
      //   - publicKey: used to verify future signatures (the private key
      //     NEVER leaves the authenticator)
      //   - counter: incremented on each use, helps detect cloned authenticators
      const newCredential = {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: attestationResponse.response?.transports || [],
        deviceType: credentialDeviceType,   // 'singleDevice' or 'multiDevice'
        backedUp: credentialBackedUp,       // true if synced (e.g., iCloud Keychain)
        createdAt: new Date().toISOString(),
      };

      user.credentials.push(newCredential);

      console.log(`  Credential stored successfully`);
      console.log(`  Credential ID: ${credential.id.substring(0, 20)}...`);
      console.log(`  Device type: ${credentialDeviceType}`);
      console.log(`  Backed up (synced): ${credentialBackedUp}`);
      console.log(`  User now has ${user.credentials.length} credential(s)`);

      // Consume the challenge (single-use)
      challengeStore.delete(username);

      return res.json({
        verified: true,
        message: `Passkey registered successfully for "${username}"!`,
        credential: {
          id: credential.id,
          deviceType: credentialDeviceType,
          backedUp: credentialBackedUp,
        },
      });
    }

    // Challenge consumed even on failure
    challengeStore.delete(username);

    return res.status(400).json({
      verified: false,
      error: 'Registration verification failed',
    });
  } catch (error) {
    console.error('  Verification error:', error.message);
    challengeStore.delete(req.body?.username);
    return res.status(500).json({ error: `Verification failed: ${error.message}` });
  }
});

// =====================================================================
// AUTHENTICATION FLOW
// =====================================================================

/**
 * Step 1 of Authentication: Generate authentication options.
 *
 * The client calls this endpoint to get the parameters needed to use
 * an existing credential. The server generates:
 *   - A random challenge
 *   - A list of allowed credential IDs (the user's registered credentials)
 *   - User verification preference
 *
 * The browser uses this to prompt the user to select and use a credential.
 */
app.post('/api/login/options', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username || typeof username !== 'string' || username.trim() === '') {
      return res.status(400).json({ error: 'Username is required' });
    }

    console.log(`\n--- AUTHENTICATION: Generating options for "${username}" ---`);

    const user = userStore.get(username);
    if (!user || user.credentials.length === 0) {
      console.log(`  ERROR: User "${username}" not found or has no credentials`);
      return res.status(404).json({
        error: `User "${username}" not found or has no registered passkeys. Register first.`,
      });
    }

    console.log(`  User has ${user.credentials.length} credential(s)`);

    // Generate authentication options
    const options = await generateAuthenticationOptions({
      rpID,
      timeout: 60000,

      // Specify which credentials the user can use
      // This helps the authenticator find the right key
      allowCredentials: user.credentials.map((cred) => ({
        id: cred.id,
        transports: cred.transports,
      })),

      // User verification (UV) preference:
      //   'preferred'    - Request UV if available (biometric/PIN), but don't require it
      //   'required'     - UV is mandatory (more secure, user must verify)
      //   'discouraged'  - Don't request UV (faster, less secure)
      //
      // UV is what makes passkeys "two-factor in one":
      //   Factor 1: Possession of the device (something you have)
      //   Factor 2: Biometric or PIN (something you are / something you know)
      userVerification: 'preferred',
    });

    // Store the challenge for verification
    challengeStore.set(username, options.challenge);

    console.log('  Authentication options generated successfully');
    console.log(`  Challenge: ${options.challenge.substring(0, 20)}...`);
    console.log(`  Allowed credentials: ${user.credentials.length}`);

    return res.json(options);
  } catch (error) {
    console.error('  Error generating authentication options:', error);
    return res.status(500).json({ error: 'Failed to generate authentication options' });
  }
});

/**
 * Step 2 of Authentication: Verify the authentication response.
 *
 * After the user selects and activates a credential, the client sends
 * the assertion response back here. The server verifies:
 *   - The challenge matches what was issued
 *   - The origin and RP ID match
 *   - The credential ID belongs to this user
 *   - The signature is valid (proves possession of the private key)
 *   - The counter has incremented (detects cloned authenticators)
 *
 * If everything checks out, the user is authenticated!
 */
app.post('/api/login/verify', async (req, res) => {
  try {
    const { username, assertionResponse } = req.body;

    if (!username || !assertionResponse) {
      return res.status(400).json({ error: 'Username and assertion response are required' });
    }

    console.log(`\n--- AUTHENTICATION: Verifying response for "${username}" ---`);

    const expectedChallenge = challengeStore.get(username);
    if (!expectedChallenge) {
      console.log('  ERROR: No challenge found - authentication options were not generated first');
      return res.status(400).json({ error: 'No challenge found. Call /api/login/options first.' });
    }

    const user = userStore.get(username);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Find the credential that was used to sign the response.
    // The assertionResponse contains the credential ID that was used.
    const credentialID = assertionResponse.id;
    const matchingCredential = user.credentials.find((cred) => cred.id === credentialID);

    if (!matchingCredential) {
      console.log(`  ERROR: Credential ${credentialID} not found for user "${username}"`);
      challengeStore.delete(username);
      return res.status(400).json({ error: 'Credential not registered for this user' });
    }

    console.log(`  Found matching credential: ${credentialID.substring(0, 20)}...`);

    // Verify the authentication response
    // This checks the signature using the stored public key
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      credential: {
        id: matchingCredential.id,
        publicKey: matchingCredential.publicKey,
        counter: matchingCredential.counter,
        transports: matchingCredential.transports,
      },
    });

    console.log(`  Verification result: ${verification.verified ? 'SUCCESS' : 'FAILED'}`);

    if (verification.verified) {
      // Update the stored counter to the new value.
      // The counter increments on each use. If the counter goes backwards
      // or stays the same, it could indicate a cloned authenticator.
      const { newCounter } = verification.authenticationInfo;
      const oldCounter = matchingCredential.counter;
      matchingCredential.counter = newCounter;

      console.log(`  Counter updated: ${oldCounter} -> ${newCounter}`);
      console.log(`  User "${username}" is now authenticated!`);

      // Consume the challenge
      challengeStore.delete(username);

      return res.json({
        verified: true,
        message: `Welcome back, "${username}"! Authentication successful.`,
        user: {
          username: user.username,
          credentialCount: user.credentials.length,
        },
      });
    }

    challengeStore.delete(username);
    return res.status(400).json({
      verified: false,
      error: 'Authentication verification failed',
    });
  } catch (error) {
    console.error('  Verification error:', error.message);
    challengeStore.delete(req.body?.username);
    return res.status(500).json({ error: `Verification failed: ${error.message}` });
  }
});

// =====================================================================
// UTILITY ENDPOINTS
// =====================================================================

/**
 * List all registered users and their credential count.
 * Useful for debugging.
 */
app.get('/api/users', (req, res) => {
  const users = [];
  for (const [username, user] of userStore) {
    users.push({
      username,
      credentialCount: user.credentials.length,
      credentials: user.credentials.map((c) => ({
        id: c.id.substring(0, 20) + '...',
        deviceType: c.deviceType,
        backedUp: c.backedUp,
        counter: c.counter,
        createdAt: c.createdAt,
      })),
    });
  }
  return res.json({ users });
});

/**
 * Serve the main HTML page.
 */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// =====================================================================
// START SERVER
// =====================================================================

app.listen(PORT, () => {
  console.log('============================================================');
  console.log(`  Passkeys (WebAuthn/FIDO2) Demo Server`);
  console.log(`  Running at: http://localhost:${PORT}`);
  console.log('');
  console.log('  This demo shows the complete passkey flow:');
  console.log('    1. Register a passkey (creates a public-private key pair)');
  console.log('    2. Login with the passkey (proves possession of private key)');
  console.log('');
  console.log('  No passwords are ever used or stored!');
  console.log('');
  console.log('  NOTE: WebAuthn requires either:');
  console.log('    - localhost (for development)');
  console.log('    - HTTPS (for production)');
  console.log('============================================================');
});
