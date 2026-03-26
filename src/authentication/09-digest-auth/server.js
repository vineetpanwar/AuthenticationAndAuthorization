/**
 * ============================================================================
 * DIGEST AUTHENTICATION (HTTP Digest Auth)
 * ============================================================================
 *
 * What is Digest Auth?
 * --------------------
 * Digest Authentication is an HTTP authentication scheme defined in RFC 2617
 * (1999) and updated in RFC 7616 (2015). Unlike Basic Auth, it NEVER sends
 * the password over the wire -- not even encoded. Instead, the client sends
 * a cryptographic hash (digest) proving it knows the password.
 *
 * How it works:
 * 1. Client requests a protected resource.
 * 2. Server responds with 401 and a WWW-Authenticate: Digest header that
 *    includes a realm, a unique nonce, and the hashing algorithm (MD5/SHA-256).
 * 3. Client computes:
 *      HA1 = hash(username : realm : password)
 *      HA2 = hash(HTTP_method : URI)
 *      response = hash(HA1 : nonce : nc : cnonce : qop : HA2)
 * 4. Client re-sends the request with an Authorization: Digest header
 *    containing username, realm, nonce, uri, nc, cnonce, qop, and response.
 * 5. Server performs the same hash computation and compares the response.
 *
 * Key advantages over Basic Auth:
 * - Password is NEVER transmitted (only its hash).
 * - Nonce prevents replay attacks.
 * - Server can expire nonces to limit attack window.
 *
 * Limitations:
 * - Server must store passwords in a reversible form (or store HA1 hashes).
 * - Vulnerable to MITM without HTTPS (attacker can downgrade to Basic).
 * - MD5 is considered weak; RFC 7616 added SHA-256 support.
 * - More complex to implement than Basic Auth.
 *
 * Run: npm run digest-auth
 * Test: curl --digest -u alice:password123 http://localhost:3012/protected
 * ============================================================================
 */

const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = 3012;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const REALM = 'Digest Auth Demo';
const ALGORITHM = 'MD5'; // RFC 7616 also supports SHA-256
const QOP = 'auth'; // Quality of protection: "auth" or "auth-int"
const NONCE_EXPIRY_MS = 5 * 60 * 1000; // Nonces expire after 5 minutes

// ---------------------------------------------------------------------------
// In-memory user store
// For Digest Auth, the server needs to compute HA1 = MD5(username:realm:password)
// In production, you'd store the pre-computed HA1 hash, never the plaintext.
// ---------------------------------------------------------------------------
const users = [
  {
    id: 1,
    username: 'alice',
    password: 'password123',
    role: 'admin',
  },
  {
    id: 2,
    username: 'bob',
    password: 'secret456',
    role: 'user',
  },
];

// Pre-compute HA1 hashes (what you'd store in a real database)
const ha1Store = {};
for (const user of users) {
  ha1Store[user.username] = md5(`${user.username}:${REALM}:${user.password}`);
  console.log(`[INIT] Pre-computed HA1 for ${user.username}`);
}

// ---------------------------------------------------------------------------
// Nonce management -- tracks issued nonces and their nonce counts
// ---------------------------------------------------------------------------
const nonceStore = new Map(); // nonce -> { createdAt, nc }

function generateNonce() {
  const nonce = crypto.randomBytes(16).toString('hex');
  nonceStore.set(nonce, { createdAt: Date.now(), nc: 0 });
  return nonce;
}

function isNonceValid(nonce) {
  const entry = nonceStore.get(nonce);
  if (!entry) return false;
  if (Date.now() - entry.createdAt > NONCE_EXPIRY_MS) {
    nonceStore.delete(nonce);
    return false;
  }
  return true;
}

function generateOpaque() {
  return crypto.randomBytes(16).toString('hex');
}

// Clean up expired nonces every minute
setInterval(() => {
  const now = Date.now();
  for (const [nonce, entry] of nonceStore) {
    if (now - entry.createdAt > NONCE_EXPIRY_MS) {
      nonceStore.delete(nonce);
    }
  }
}, 60 * 1000);

// ---------------------------------------------------------------------------
// Helper: MD5 hash
// ---------------------------------------------------------------------------
function md5(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

// ---------------------------------------------------------------------------
// Parse the Authorization: Digest header
// ---------------------------------------------------------------------------
function parseDigestHeader(header) {
  const params = {};
  // Match key="value" or key=value pairs
  const regex = /(\w+)=(?:"([^"]+)"|([^\s,]+))/g;
  let match;
  while ((match = regex.exec(header)) !== null) {
    params[match[1]] = match[2] || match[3];
  }
  return params;
}

// ---------------------------------------------------------------------------
// Digest Auth Middleware
// ---------------------------------------------------------------------------
function digestAuthMiddleware(req, res, next) {
  console.log(`\n[REQUEST] ${req.method} ${req.path}`);

  const authHeader = req.headers.authorization;

  // Step 1: No credentials -- challenge the client
  if (!authHeader || !authHeader.startsWith('Digest ')) {
    console.log('[AUTH] No Digest credentials -- sending challenge');
    return sendChallenge(res);
  }

  // Step 2: Parse the Digest response
  const params = parseDigestHeader(authHeader);
  console.log(`[AUTH] Digest response from user: ${params.username}`);

  const { username, realm, nonce, uri, nc, cnonce, qop, response } = params;

  // Step 3: Validate required fields
  if (!username || !realm || !nonce || !uri || !response) {
    console.log('[AUTH] Missing required Digest fields');
    return sendChallenge(res);
  }

  // Step 4: Validate realm
  if (realm !== REALM) {
    console.log(`[AUTH] Realm mismatch: expected "${REALM}", got "${realm}"`);
    return sendChallenge(res);
  }

  // Step 5: Validate nonce
  if (!isNonceValid(nonce)) {
    console.log('[AUTH] Nonce is expired or unknown -- sending new challenge (stale=true)');
    return sendChallenge(res, true);
  }

  // Step 6: Check nonce count to prevent replay
  const nonceEntry = nonceStore.get(nonce);
  const ncValue = parseInt(nc, 16);
  if (ncValue <= nonceEntry.nc) {
    console.log(`[AUTH] Nonce count replay detected: received ${ncValue}, expected > ${nonceEntry.nc}`);
    return sendChallenge(res);
  }
  nonceEntry.nc = ncValue;

  // Step 7: Look up the user's HA1
  const storedHA1 = ha1Store[username];
  if (!storedHA1) {
    console.log(`[AUTH] Unknown user: ${username}`);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Step 8: Compute the expected response
  // HA1 = MD5(username:realm:password)   -- already pre-computed
  // HA2 = MD5(method:digestURI)
  const ha2 = md5(`${req.method}:${uri}`);

  let expectedResponse;
  if (qop === 'auth' || qop === 'auth-int') {
    // response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
    expectedResponse = md5(`${storedHA1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
  } else {
    // Legacy: response = MD5(HA1:nonce:HA2)
    expectedResponse = md5(`${storedHA1}:${nonce}:${ha2}`);
  }

  // Step 9: Compare (constant-time to prevent timing attacks)
  if (!crypto.timingSafeEqual(Buffer.from(response), Buffer.from(expectedResponse))) {
    console.log('[AUTH] Digest response mismatch -- invalid password');
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  console.log(`[AUTH] User "${username}" authenticated via Digest Auth`);

  // Attach user to request
  const user = users.find((u) => u.username === username);
  req.user = { id: user.id, username: user.username, role: user.role };
  next();
}

// ---------------------------------------------------------------------------
// Send a 401 challenge with WWW-Authenticate: Digest header
// ---------------------------------------------------------------------------
function sendChallenge(res, stale = false) {
  const nonce = generateNonce();
  const opaque = generateOpaque();

  const parts = [
    `realm="${REALM}"`,
    `qop="${QOP}"`,
    `nonce="${nonce}"`,
    `opaque="${opaque}"`,
    `algorithm=${ALGORITHM}`,
  ];
  if (stale) parts.push('stale=true');

  res.set('WWW-Authenticate', `Digest ${parts.join(', ')}`);
  return res.status(401).json({
    error: 'Authentication required',
    message: 'Please authenticate using HTTP Digest Authentication',
    hint: 'curl --digest -u username:password http://localhost:3012/protected',
  });
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Public route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to the Digest Auth demo server',
    description: 'Unlike Basic Auth, Digest Auth never sends your password over the wire',
    endpoints: {
      'GET /': 'This help message (public)',
      'GET /protected': 'Protected resource (requires Digest Auth)',
      'GET /admin': 'Admin-only resource (requires Digest Auth + admin role)',
      'GET /how-it-works': 'Step-by-step explanation of the Digest Auth flow',
    },
    usage: 'curl --digest -u alice:password123 http://localhost:3012/protected',
  });
});

// Explain the flow
app.get('/how-it-works', (req, res) => {
  res.json({
    title: 'How Digest Authentication Works',
    steps: [
      {
        step: 1,
        description: 'Client requests a protected resource without credentials',
      },
      {
        step: 2,
        description: 'Server responds with 401 and WWW-Authenticate: Digest header containing realm, nonce, qop, and algorithm',
      },
      {
        step: 3,
        description: 'Client computes HA1 = MD5(username:realm:password)',
      },
      {
        step: 4,
        description: 'Client computes HA2 = MD5(HTTP_method:URI)',
      },
      {
        step: 5,
        description: 'Client computes response = MD5(HA1:nonce:nc:cnonce:qop:HA2)',
      },
      {
        step: 6,
        description: 'Client sends Authorization: Digest header with username, realm, nonce, uri, nc, cnonce, qop, response',
      },
      {
        step: 7,
        description: 'Server computes the same hash and compares. If they match, the client proved it knows the password WITHOUT sending it.',
      },
    ],
    key_fields: {
      realm: 'Protection space identifier (e.g., "admin@example.com")',
      nonce: 'Server-generated one-time value to prevent replay attacks',
      nc: 'Nonce count -- client increments this with each request using the same nonce',
      cnonce: 'Client-generated nonce to prevent chosen-plaintext attacks',
      qop: 'Quality of protection: "auth" (authentication) or "auth-int" (authentication + integrity)',
      opaque: 'Server state passed back unchanged by the client',
    },
  });
});

// Protected route
app.get('/protected', digestAuthMiddleware, (req, res) => {
  res.json({
    message: 'You have accessed a protected resource via Digest Auth!',
    note: 'Your password was NEVER sent over the network -- only a hash proving you know it.',
    user: req.user,
    timestamp: new Date().toISOString(),
  });
});

// Admin-only route
app.get('/admin', digestAuthMiddleware, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Admin access required',
    });
  }

  res.json({
    message: 'Welcome, admin!',
    user: req.user,
    adminData: {
      totalUsers: users.length,
      activeNonces: nonceStore.size,
      serverUptime: process.uptime(),
    },
  });
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------
app.use((err, req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal Server Error', message: err.message });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`\n========================================`);
  console.log(`  Digest Auth Server running on port ${PORT}`);
  console.log(`========================================`);
  console.log(`\nAvailable users: alice:password123 (admin), bob:secret456 (user)`);
  console.log(`\nTest commands:`);
  console.log(`  curl http://localhost:${PORT}/`);
  console.log(`  curl --digest -u alice:password123 http://localhost:${PORT}/protected`);
  console.log(`  curl --digest -u bob:secret456 http://localhost:${PORT}/protected`);
  console.log(`  curl --digest -u alice:password123 http://localhost:${PORT}/admin`);
  console.log(`  curl http://localhost:${PORT}/how-it-works`);
});
