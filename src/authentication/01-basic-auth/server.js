/**
 * ============================================================================
 * BASIC AUTHENTICATION (HTTP Basic Auth)
 * ============================================================================
 *
 * What is Basic Auth?
 * -------------------
 * Basic Authentication is the simplest HTTP authentication scheme defined in
 * RFC 7617. The client sends the username and password encoded in Base64 in
 * the Authorization header with every request.
 *
 * How it works:
 * 1. Client sends a request to a protected resource.
 * 2. Server responds with 401 Unauthorized and a WWW-Authenticate header.
 * 3. Client re-sends the request with an Authorization header:
 *      Authorization: Basic base64(username:password)
 * 4. Server decodes the Base64 string, extracts username:password, and
 *    validates the credentials against its user store.
 *
 * Security considerations:
 * - Credentials are Base64-encoded, NOT encrypted. Always use HTTPS.
 * - Credentials are sent with EVERY request, increasing exposure risk.
 * - No built-in session management or token expiration.
 * - Best suited for server-to-server communication or simple internal tools.
 *
 * Run: npm run basic-auth
 * Test: curl -u alice:password123 http://localhost:3001/protected
 * ============================================================================
 */

const express = require('express');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3001;

// ---------------------------------------------------------------------------
// In-memory user store with bcrypt-hashed passwords
// In production, this would be a database (e.g., PostgreSQL, MongoDB).
// ---------------------------------------------------------------------------
const users = [];

/**
 * Initialize users with bcrypt-hashed passwords.
 * bcrypt automatically handles salting -- each hash is unique even for
 * the same plaintext password.
 */
async function initializeUsers() {
  const saltRounds = 10; // Cost factor for bcrypt hashing

  users.push({
    id: 1,
    username: 'alice',
    // Hash the password so we never store plaintext
    passwordHash: await bcrypt.hash('password123', saltRounds),
    role: 'admin',
  });

  users.push({
    id: 2,
    username: 'bob',
    passwordHash: await bcrypt.hash('secret456', saltRounds),
    role: 'user',
  });

  console.log('[INIT] Users initialized with bcrypt-hashed passwords');
  console.log('[INIT] Available users: alice:password123, bob:secret456');
}

// ---------------------------------------------------------------------------
// Basic Auth Middleware
// ---------------------------------------------------------------------------
/**
 * Middleware that extracts and validates Basic Auth credentials.
 *
 * The Authorization header format is:
 *   Authorization: Basic <base64(username:password)>
 *
 * Steps:
 * 1. Check for the Authorization header.
 * 2. Verify it starts with "Basic ".
 * 3. Decode the Base64 portion to get "username:password".
 * 4. Split on ":" to extract username and password.
 * 5. Look up the user and compare the password hash with bcrypt.
 */
async function basicAuthMiddleware(req, res, next) {
  console.log(`\n[REQUEST] ${req.method} ${req.path}`);

  // Step 1: Check for the Authorization header
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    console.log('[AUTH] No Authorization header present');
    // The WWW-Authenticate header tells the client which auth scheme to use
    res.set('WWW-Authenticate', 'Basic realm="Secure Area"');
    return res.status(401).json({
      error: 'Authentication required',
      message: 'Please provide credentials via Basic Auth',
    });
  }

  // Step 2: Verify the header starts with "Basic "
  if (!authHeader.startsWith('Basic ')) {
    console.log('[AUTH] Authorization header is not Basic scheme');
    return res.status(401).json({
      error: 'Invalid authentication scheme',
      message: 'Expected Basic authentication',
    });
  }

  // Step 3: Decode the Base64 credentials
  const base64Credentials = authHeader.split(' ')[1];
  const decodedCredentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
  console.log(`[AUTH] Decoded credentials string (username:****)`);

  // Step 4: Split into username and password
  // Note: we use indexOf to handle passwords that contain ":"
  const separatorIndex = decodedCredentials.indexOf(':');
  if (separatorIndex === -1) {
    console.log('[AUTH] Malformed credentials -- missing ":" separator');
    return res.status(401).json({
      error: 'Malformed credentials',
      message: 'Credentials must be in the format username:password',
    });
  }

  const username = decodedCredentials.substring(0, separatorIndex);
  const password = decodedCredentials.substring(separatorIndex + 1);
  console.log(`[AUTH] Attempting login for user: ${username}`);

  // Step 5: Look up user and validate password with bcrypt
  const user = users.find((u) => u.username === username);

  if (!user) {
    console.log(`[AUTH] User "${username}" not found`);
    return res.status(401).json({
      error: 'Invalid credentials',
      message: 'Username or password is incorrect',
    });
  }

  // bcrypt.compare hashes the provided password with the same salt and
  // compares the result to the stored hash -- constant-time comparison
  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

  if (!isPasswordValid) {
    console.log(`[AUTH] Invalid password for user "${username}"`);
    return res.status(401).json({
      error: 'Invalid credentials',
      message: 'Username or password is incorrect',
    });
  }

  console.log(`[AUTH] User "${username}" authenticated successfully`);

  // Attach user info to the request object for downstream route handlers
  req.user = {
    id: user.id,
    username: user.username,
    role: user.role,
  };

  next();
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Public route -- no authentication required
app.get('/', (req, res) => {
  console.log('\n[REQUEST] GET / (public)');
  res.json({
    message: 'Welcome to the Basic Auth demo server',
    endpoints: {
      'GET /': 'This help message (public)',
      'GET /protected': 'Protected resource (requires Basic Auth)',
      'GET /admin': 'Admin-only resource (requires Basic Auth + admin role)',
    },
    usage: 'curl -u username:password http://localhost:3001/protected',
  });
});

// Protected route -- requires valid Basic Auth credentials
app.get('/protected', basicAuthMiddleware, (req, res) => {
  console.log(`[RESPONSE] Serving protected resource for ${req.user.username}`);
  res.json({
    message: 'You have accessed a protected resource!',
    user: req.user,
    timestamp: new Date().toISOString(),
  });
});

// Admin-only route -- requires Basic Auth + admin role
app.get('/admin', basicAuthMiddleware, (req, res) => {
  // Check role after authentication
  if (req.user.role !== 'admin') {
    console.log(`[AUTH] User "${req.user.username}" denied access to admin route (role: ${req.user.role})`);
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Admin access required',
    });
  }

  console.log(`[RESPONSE] Serving admin resource for ${req.user.username}`);
  res.json({
    message: 'Welcome, admin!',
    user: req.user,
    adminData: {
      totalUsers: users.length,
      serverUptime: process.uptime(),
    },
  });
});

// ---------------------------------------------------------------------------
// Error handling middleware
// ---------------------------------------------------------------------------
app.use((err, req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message,
  });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
initializeUsers().then(() => {
  app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`  Basic Auth Server running on port ${PORT}`);
    console.log(`========================================`);
    console.log(`\nTest commands:`);
    console.log(`  curl http://localhost:${PORT}/`);
    console.log(`  curl -u alice:password123 http://localhost:${PORT}/protected`);
    console.log(`  curl -u bob:secret456 http://localhost:${PORT}/protected`);
    console.log(`  curl -u alice:password123 http://localhost:${PORT}/admin`);
    console.log(`  curl -u bob:secret456 http://localhost:${PORT}/admin  # (will be 403)`);
  });
});
