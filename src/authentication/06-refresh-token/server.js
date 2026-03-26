/**
 * ============================================================================
 * ACCESS TOKEN + REFRESH TOKEN AUTHENTICATION
 * ============================================================================
 *
 * What is the Access + Refresh Token pattern?
 * -------------------------------------------
 * This pattern uses TWO tokens to balance security and user experience:
 *
 * 1. Access Token (short-lived, e.g., 15 minutes):
 *    - A JWT used to authenticate API requests.
 *    - Short expiry limits the damage if stolen.
 *    - Sent in the Authorization header with every request.
 *
 * 2. Refresh Token (long-lived, e.g., 7 days):
 *    - An opaque token stored server-side.
 *    - Used ONLY to obtain a new access token when the old one expires.
 *    - Never sent to resource endpoints -- only to the /refresh endpoint.
 *    - Can be revoked server-side for instant session termination.
 *
 * How it works:
 * 1. Client logs in with credentials.
 * 2. Server returns an access token (JWT, 15min) and a refresh token (7 days).
 * 3. Client uses the access token for API requests.
 * 4. When the access token expires, client sends the refresh token to /refresh.
 * 5. Server validates the refresh token and issues a NEW access token.
 * 6. Server also issues a NEW refresh token (token rotation) and invalidates
 *    the old one, preventing replay attacks.
 * 7. On logout, the refresh token is invalidated.
 *
 * Token Rotation:
 * - Each time a refresh token is used, a NEW refresh token is issued.
 * - The old refresh token is immediately invalidated.
 * - If an attacker steals a refresh token and uses it, the legitimate user's
 *   next refresh will fail (because the token was already rotated), alerting
 *   them to a potential breach.
 *
 * Why this pattern?
 * - Access tokens are stateless (JWT) -> fast verification, no DB lookup.
 * - Short access token life -> less exposure if stolen.
 * - Refresh tokens are stateful -> can be instantly revoked.
 * - Token rotation -> detects token theft.
 * - Users stay logged in without re-entering credentials frequently.
 *
 * Run: npm run refresh-token
 * ============================================================================
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3006;

app.use(express.json());

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const ACCESS_TOKEN_SECRET = 'access-token-secret-change-in-production';
const REFRESH_TOKEN_SECRET = 'refresh-token-secret-change-in-production';
const ACCESS_TOKEN_EXPIRY = '15m';  // Short-lived: 15 minutes
const REFRESH_TOKEN_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000; // Long-lived: 7 days

// ---------------------------------------------------------------------------
// In-memory stores
// ---------------------------------------------------------------------------
const users = [];

/**
 * Refresh token store.
 * Maps: refreshToken (string) -> { userId, username, expiresAt, family }
 *
 * The "family" field groups refresh tokens from the same login session.
 * If a token from the same family is used after rotation, it indicates
 * potential token theft, and all tokens in the family should be revoked.
 */
const refreshTokenStore = new Map();

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

  console.log('[INIT] Users initialized: alice:password123, bob:secret456');
}

// ---------------------------------------------------------------------------
// Token Creation Functions
// ---------------------------------------------------------------------------

/**
 * Creates a short-lived access token (JWT).
 */
function createAccessToken(user) {
  const payload = {
    sub: user.id.toString(),
    username: user.username,
    role: user.role,
    type: 'access', // Clearly mark this as an access token
  };

  const token = jwt.sign(payload, ACCESS_TOKEN_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRY,
    algorithm: 'HS256',
  });

  console.log(`[TOKEN] Access token created for "${user.username}" (expires in ${ACCESS_TOKEN_EXPIRY})`);
  return token;
}

/**
 * Creates a long-lived refresh token (opaque UUID) and stores it.
 *
 * @param {object} user - The user object.
 * @param {string} family - Token family ID (new family for login, same for refresh).
 */
function createRefreshToken(user, family) {
  const token = uuidv4();
  const expiresAt = Date.now() + REFRESH_TOKEN_EXPIRY_MS;

  refreshTokenStore.set(token, {
    userId: user.id,
    username: user.username,
    expiresAt,
    family,
    createdAt: Date.now(),
  });

  console.log(`[TOKEN] Refresh token created for "${user.username}" (family: ${family.substring(0, 8)}...)`);
  console.log(`[TOKEN] Active refresh tokens: ${refreshTokenStore.size}`);

  return {
    token,
    expiresAt: new Date(expiresAt).toISOString(),
  };
}

/**
 * Invalidates all refresh tokens in a given family.
 * Used when token theft is detected.
 */
function invalidateTokenFamily(family) {
  let count = 0;
  for (const [token, data] of refreshTokenStore) {
    if (data.family === family) {
      refreshTokenStore.delete(token);
      count++;
    }
  }
  console.log(`[SECURITY] Invalidated ${count} tokens in family ${family.substring(0, 8)}...`);
}

// ---------------------------------------------------------------------------
// Access Token Verification Middleware
// ---------------------------------------------------------------------------
function verifyAccessToken(req, res, next) {
  console.log(`\n[REQUEST] ${req.method} ${req.path}`);

  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Authentication required',
      message: 'Provide an access token: Authorization: Bearer <token>',
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET, {
      algorithms: ['HS256'],
    });

    // Ensure this is an access token, not a refresh token
    if (decoded.type !== 'access') {
      return res.status(401).json({
        error: 'Invalid token type',
        message: 'Expected an access token, not a refresh token',
      });
    }

    console.log(`[JWT] Valid access token for "${decoded.username}"`);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      console.log('[JWT] Access token expired');
      return res.status(401).json({
        error: 'Token expired',
        message: 'Access token has expired. Use your refresh token to get a new one.',
        hint: 'POST /refresh with { "refreshToken": "your-refresh-token" }',
      });
    }

    console.log(`[JWT] Invalid access token: ${err.message}`);
    return res.status(401).json({
      error: 'Invalid token',
      message: err.message,
    });
  }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Public info route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to the Access + Refresh Token demo server',
    endpoints: {
      'POST /login': 'Login to receive access + refresh tokens',
      'POST /refresh': 'Exchange refresh token for new access token',
      'GET /protected': 'Protected resource (requires access token)',
      'POST /logout': 'Invalidate refresh token',
      'GET /token-info': 'View your token claims (requires access token)',
    },
    tokenLifetimes: {
      accessToken: ACCESS_TOKEN_EXPIRY,
      refreshToken: '7 days',
    },
    flow: [
      '1. POST /login -> get access_token + refresh_token',
      '2. Use access_token for API requests (15 min)',
      '3. When access_token expires, POST /refresh with refresh_token',
      '4. Get new access_token + new refresh_token (rotation)',
      '5. Old refresh_token is invalidated',
    ],
  });
});

/**
 * Login endpoint.
 * Returns both an access token and a refresh token.
 */
app.post('/login', async (req, res) => {
  console.log('\n[REQUEST] POST /login');

  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      error: 'Bad request',
      message: 'Username and password are required',
    });
  }

  const user = users.find((u) => u.username === username);

  if (!user) {
    return res.status(401).json({
      error: 'Invalid credentials',
      message: 'Username or password is incorrect',
    });
  }

  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

  if (!isPasswordValid) {
    return res.status(401).json({
      error: 'Invalid credentials',
      message: 'Username or password is incorrect',
    });
  }

  // Create a new token family for this login session
  const family = uuidv4();

  // Issue both tokens
  const accessToken = createAccessToken(user);
  const refreshToken = createRefreshToken(user, family);

  console.log(`[LOGIN] User "${username}" logged in (new family: ${family.substring(0, 8)}...)`);

  res.json({
    message: 'Login successful',
    accessToken: accessToken,
    refreshToken: refreshToken.token,
    refreshTokenExpiresAt: refreshToken.expiresAt,
    tokenType: 'Bearer',
    expiresIn: ACCESS_TOKEN_EXPIRY,
    usage: {
      accessToken: 'Authorization: Bearer <access_token>',
      refreshToken: 'POST /refresh with { "refreshToken": "<refresh_token>" }',
    },
  });
});

/**
 * Refresh endpoint.
 * Exchanges a valid refresh token for a new access token.
 * Implements token rotation: old refresh token is invalidated,
 * new refresh token is issued.
 */
app.post('/refresh', (req, res) => {
  console.log('\n[REQUEST] POST /refresh');

  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({
      error: 'Bad request',
      message: 'Refresh token is required',
    });
  }

  // Look up the refresh token
  const tokenData = refreshTokenStore.get(refreshToken);

  if (!tokenData) {
    console.log('[REFRESH] Invalid or already-used refresh token');
    // This could indicate token theft -- the token was already rotated
    // but someone is trying to use the old one.
    // In a real system, you might want to invalidate all tokens for this user.
    return res.status(401).json({
      error: 'Invalid refresh token',
      message: 'This refresh token is invalid or has already been used. If you did not rotate this token, your session may have been compromised.',
    });
  }

  // Check if the refresh token has expired
  if (Date.now() > tokenData.expiresAt) {
    console.log(`[REFRESH] Expired refresh token for "${tokenData.username}"`);
    refreshTokenStore.delete(refreshToken);
    return res.status(401).json({
      error: 'Refresh token expired',
      message: 'Your refresh token has expired. Please login again.',
    });
  }

  // Find the user
  const user = users.find((u) => u.id === tokenData.userId);

  if (!user) {
    console.log('[REFRESH] User not found');
    refreshTokenStore.delete(refreshToken);
    return res.status(401).json({
      error: 'User not found',
      message: 'The user associated with this token no longer exists.',
    });
  }

  // ---- TOKEN ROTATION ----
  // 1. Invalidate the old refresh token
  console.log(`[ROTATION] Invalidating old refresh token for "${user.username}"`);
  refreshTokenStore.delete(refreshToken);

  // 2. Issue a new access token
  const newAccessToken = createAccessToken(user);

  // 3. Issue a new refresh token (same family)
  const newRefreshToken = createRefreshToken(user, tokenData.family);

  console.log(`[REFRESH] Tokens rotated for "${user.username}"`);

  res.json({
    message: 'Tokens refreshed successfully',
    accessToken: newAccessToken,
    refreshToken: newRefreshToken.token,
    refreshTokenExpiresAt: newRefreshToken.expiresAt,
    tokenType: 'Bearer',
    expiresIn: ACCESS_TOKEN_EXPIRY,
    note: 'Your old refresh token has been invalidated. Use the new one.',
  });
});

/**
 * Logout endpoint.
 * Invalidates the refresh token (and optionally all tokens in the family).
 */
app.post('/logout', (req, res) => {
  console.log('\n[REQUEST] POST /logout');

  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({
      error: 'Bad request',
      message: 'Refresh token is required to logout',
    });
  }

  const tokenData = refreshTokenStore.get(refreshToken);

  if (tokenData) {
    // Invalidate ALL tokens in this family (revoke the entire session)
    console.log(`[LOGOUT] Revoking session for "${tokenData.username}"`);
    invalidateTokenFamily(tokenData.family);
  } else {
    console.log('[LOGOUT] Refresh token not found (may already be invalidated)');
  }

  res.json({
    message: 'Logged out successfully',
    info: 'All tokens for this session have been invalidated.',
    note: 'Your access token may still work until it expires (up to 15 minutes). For instant revocation, implement a token blacklist.',
  });
});

// Protected route
app.get('/protected', verifyAccessToken, (req, res) => {
  console.log(`[RESPONSE] Protected resource for "${req.user.username}"`);
  res.json({
    message: 'You have accessed a protected resource!',
    user: {
      id: req.user.sub,
      username: req.user.username,
      role: req.user.role,
    },
    tokenInfo: {
      issuedAt: new Date(req.user.iat * 1000).toISOString(),
      expiresAt: new Date(req.user.exp * 1000).toISOString(),
      remainingSeconds: Math.max(0, req.user.exp - Math.floor(Date.now() / 1000)),
    },
  });
});

// View token claims
app.get('/token-info', verifyAccessToken, (req, res) => {
  res.json({
    message: 'Your access token information',
    claims: req.user,
    timing: {
      issuedAt: new Date(req.user.iat * 1000).toISOString(),
      expiresAt: new Date(req.user.exp * 1000).toISOString(),
      remainingSeconds: Math.max(0, req.user.exp - Math.floor(Date.now() / 1000)),
    },
    activeRefreshTokens: refreshTokenStore.size,
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
// Periodic cleanup of expired refresh tokens
// ---------------------------------------------------------------------------
setInterval(() => {
  let cleaned = 0;
  for (const [token, data] of refreshTokenStore) {
    if (Date.now() > data.expiresAt) {
      refreshTokenStore.delete(token);
      cleaned++;
    }
  }
  if (cleaned > 0) {
    console.log(`[CLEANUP] Removed ${cleaned} expired refresh tokens`);
  }
}, 60 * 60 * 1000); // Run every hour

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
initializeUsers().then(() => {
  app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`  Refresh Token Server running on port ${PORT}`);
    console.log(`========================================`);
    console.log(`\nToken lifetimes:`);
    console.log(`  Access token:  ${ACCESS_TOKEN_EXPIRY}`);
    console.log(`  Refresh token: 7 days`);
    console.log(`\nTest commands:`);
    console.log(`  # Login:`);
    console.log(`  curl -X POST http://localhost:${PORT}/login \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"username":"alice","password":"password123"}'`);
    console.log(`\n  # Access protected resource:`);
    console.log(`  curl http://localhost:${PORT}/protected \\`);
    console.log(`    -H "Authorization: Bearer <ACCESS_TOKEN>"`);
    console.log(`\n  # Refresh tokens:`);
    console.log(`  curl -X POST http://localhost:${PORT}/refresh \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"refreshToken":"<REFRESH_TOKEN>"}'`);
    console.log(`\n  # Logout:`);
    console.log(`  curl -X POST http://localhost:${PORT}/logout \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"refreshToken":"<REFRESH_TOKEN>"}'`);
  });
});
