/**
 * ============================================================================
 * BEARER TOKEN AUTHENTICATION
 * ============================================================================
 *
 * What is Bearer Token Auth?
 * --------------------------
 * Bearer Token authentication is defined in RFC 6750. The client first
 * authenticates (e.g., via login) and receives an opaque token. This token
 * is then sent in the Authorization header of subsequent requests:
 *
 *   Authorization: Bearer <token>
 *
 * How it works:
 * 1. Client sends credentials to a login endpoint.
 * 2. Server validates credentials and issues an opaque bearer token.
 * 3. Client includes the token in the Authorization header for each request.
 * 4. Server looks up the token in its store to identify the user.
 * 5. On logout, the token is removed from the store (invalidated).
 *
 * Key characteristics:
 * - The token is "opaque" -- it has no inherent meaning; it's just a random
 *   string. The server must look it up in a store (memory, DB, Redis).
 * - Unlike JWT, the server is stateful -- it must maintain the token store.
 * - Tokens can be easily revoked by deleting them from the store.
 * - Simple to implement, but doesn't scale as well as stateless JWT.
 *
 * Bearer vs JWT:
 * - Bearer tokens are opaque (random UUIDs); JWT tokens are self-contained.
 * - Bearer tokens require server-side lookup; JWT tokens are verified by
 *   signature alone.
 * - Bearer tokens are easily revocable; JWT tokens require extra mechanisms
 *   (blocklists) for revocation.
 *
 * Run: npm run bearer-token
 * ============================================================================
 */

const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3002;

// Parse JSON request bodies
app.use(express.json());

// ---------------------------------------------------------------------------
// In-memory user store
// ---------------------------------------------------------------------------
const users = [];

async function initializeUsers() {
  const saltRounds = 10;

  users.push({
    id: 1,
    username: 'alice',
    passwordHash: await bcrypt.hash('password123', saltRounds),
    role: 'admin',
  });

  users.push({
    id: 2,
    username: 'bob',
    passwordHash: await bcrypt.hash('secret456', saltRounds),
    role: 'user',
  });

  console.log('[INIT] Users initialized');
}

// ---------------------------------------------------------------------------
// Token store (in-memory Map)
// Maps: token (string) -> { userId, username, role, createdAt, expiresAt }
//
// In production, use Redis or a database for persistence and scalability.
// ---------------------------------------------------------------------------
const tokenStore = new Map();

// Token expiration time (1 hour in milliseconds)
const TOKEN_EXPIRY_MS = 60 * 60 * 1000;

/**
 * Creates a new bearer token for a user and stores it.
 * Returns the token string.
 */
function createToken(user) {
  // Generate a random UUID as the opaque token
  const token = uuidv4();
  const now = Date.now();

  const tokenData = {
    userId: user.id,
    username: user.username,
    role: user.role,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + TOKEN_EXPIRY_MS).toISOString(),
    expiresAtMs: now + TOKEN_EXPIRY_MS,
  };

  tokenStore.set(token, tokenData);
  console.log(`[TOKEN] Created token for user "${user.username}" (expires in 1 hour)`);
  console.log(`[TOKEN] Active tokens: ${tokenStore.size}`);

  return token;
}

// ---------------------------------------------------------------------------
// Bearer Token Middleware
// ---------------------------------------------------------------------------
/**
 * Middleware that validates Bearer tokens from the Authorization header.
 *
 * Steps:
 * 1. Extract the Authorization header.
 * 2. Verify it uses the "Bearer" scheme.
 * 3. Look up the token in the token store.
 * 4. Check if the token has expired.
 * 5. Attach user info to req.user.
 */
function bearerAuthMiddleware(req, res, next) {
  console.log(`\n[REQUEST] ${req.method} ${req.path}`);

  // Step 1: Extract the Authorization header
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    console.log('[AUTH] No Authorization header present');
    return res.status(401).json({
      error: 'Authentication required',
      message: 'Please provide a Bearer token in the Authorization header',
    });
  }

  // Step 2: Verify it uses the "Bearer" scheme
  if (!authHeader.startsWith('Bearer ')) {
    console.log('[AUTH] Authorization header is not Bearer scheme');
    return res.status(401).json({
      error: 'Invalid authentication scheme',
      message: 'Expected Bearer token authentication',
    });
  }

  // Step 3: Extract and look up the token
  const token = authHeader.split(' ')[1];

  if (!token) {
    console.log('[AUTH] Empty token');
    return res.status(401).json({
      error: 'Invalid token',
      message: 'Token is empty',
    });
  }

  const tokenData = tokenStore.get(token);

  if (!tokenData) {
    console.log('[AUTH] Token not found in store (invalid or revoked)');
    return res.status(401).json({
      error: 'Invalid token',
      message: 'Token is invalid or has been revoked',
    });
  }

  // Step 4: Check if the token has expired
  if (Date.now() > tokenData.expiresAtMs) {
    console.log(`[AUTH] Token expired for user "${tokenData.username}"`);
    // Clean up expired token
    tokenStore.delete(token);
    return res.status(401).json({
      error: 'Token expired',
      message: 'Your token has expired. Please login again.',
    });
  }

  console.log(`[AUTH] Valid token for user "${tokenData.username}"`);

  // Step 5: Attach user info to the request
  req.user = {
    id: tokenData.userId,
    username: tokenData.username,
    role: tokenData.role,
  };
  // Store the token on the request so logout can reference it
  req.token = token;

  next();
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Public info route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to the Bearer Token Auth demo server',
    endpoints: {
      'POST /login': 'Login with username & password to receive a bearer token',
      'GET /protected': 'Protected resource (requires Bearer token)',
      'GET /profile': 'User profile (requires Bearer token)',
      'POST /logout': 'Invalidate your bearer token',
      'GET /admin/tokens': 'View active tokens (admin only)',
    },
  });
});

/**
 * Login endpoint.
 * Accepts JSON body: { "username": "...", "password": "..." }
 * Returns a bearer token on success.
 */
app.post('/login', async (req, res) => {
  console.log('\n[REQUEST] POST /login');

  const { username, password } = req.body;

  if (!username || !password) {
    console.log('[LOGIN] Missing username or password');
    return res.status(400).json({
      error: 'Bad request',
      message: 'Username and password are required',
    });
  }

  // Find user by username
  const user = users.find((u) => u.username === username);

  if (!user) {
    console.log(`[LOGIN] User "${username}" not found`);
    return res.status(401).json({
      error: 'Invalid credentials',
      message: 'Username or password is incorrect',
    });
  }

  // Verify password
  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

  if (!isPasswordValid) {
    console.log(`[LOGIN] Invalid password for user "${username}"`);
    return res.status(401).json({
      error: 'Invalid credentials',
      message: 'Username or password is incorrect',
    });
  }

  // Create and return a bearer token
  const token = createToken(user);

  console.log(`[LOGIN] User "${username}" logged in successfully`);

  res.json({
    message: 'Login successful',
    token: token,
    tokenType: 'Bearer',
    expiresIn: '1 hour',
    usage: `Include header: Authorization: Bearer ${token}`,
  });
});

// Protected route
app.get('/protected', bearerAuthMiddleware, (req, res) => {
  console.log(`[RESPONSE] Serving protected resource for ${req.user.username}`);
  res.json({
    message: 'You have accessed a protected resource!',
    user: req.user,
    timestamp: new Date().toISOString(),
  });
});

// User profile route
app.get('/profile', bearerAuthMiddleware, (req, res) => {
  console.log(`[RESPONSE] Serving profile for ${req.user.username}`);
  const user = users.find((u) => u.id === req.user.id);
  res.json({
    message: 'User profile',
    profile: {
      id: user.id,
      username: user.username,
      role: user.role,
    },
  });
});

/**
 * Logout endpoint.
 * Invalidates the bearer token by removing it from the store.
 */
app.post('/logout', bearerAuthMiddleware, (req, res) => {
  console.log(`\n[LOGOUT] Invalidating token for user "${req.user.username}"`);

  // Remove the token from the store
  tokenStore.delete(req.token);

  console.log(`[LOGOUT] Token removed. Active tokens: ${tokenStore.size}`);

  res.json({
    message: 'Logged out successfully',
    info: 'Your token has been invalidated',
  });
});

// Admin route -- view active tokens (admin only)
app.get('/admin/tokens', bearerAuthMiddleware, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      error: 'Forbidden',
      message: 'Admin access required',
    });
  }

  // List active tokens (without showing the actual token values for security)
  const activeTokens = [];
  for (const [token, data] of tokenStore) {
    activeTokens.push({
      tokenPrefix: token.substring(0, 8) + '...',
      username: data.username,
      createdAt: data.createdAt,
      expiresAt: data.expiresAt,
    });
  }

  res.json({
    activeTokenCount: tokenStore.size,
    tokens: activeTokens,
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
    console.log(`  Bearer Token Server running on port ${PORT}`);
    console.log(`========================================`);
    console.log(`\nTest commands:`);
    console.log(`  # Login to get a token:`);
    console.log(`  curl -X POST http://localhost:${PORT}/login \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"username":"alice","password":"password123"}'`);
    console.log(`\n  # Use the token:`);
    console.log(`  curl http://localhost:${PORT}/protected \\`);
    console.log(`    -H "Authorization: Bearer <YOUR_TOKEN>"`);
    console.log(`\n  # Logout:`);
    console.log(`  curl -X POST http://localhost:${PORT}/logout \\`);
    console.log(`    -H "Authorization: Bearer <YOUR_TOKEN>"`);
  });
});
