/**
 * ============================================================================
 * JWT (JSON WEB TOKEN) AUTHENTICATION
 * ============================================================================
 *
 * What is JWT?
 * ------------
 * JSON Web Token (RFC 7519) is an open standard for securely transmitting
 * information between parties as a JSON object. JWTs are digitally signed,
 * so they can be verified and trusted.
 *
 * JWT Structure (three parts separated by dots):
 * -----------------------------------------------
 *   header.payload.signature
 *
 *   1. Header: Algorithm and token type
 *      { "alg": "HS256", "typ": "JWT" }
 *
 *   2. Payload (Claims): User data and metadata
 *      {
 *        "sub": "1234567890",     // Subject (user ID)
 *        "name": "Alice",         // Custom claim
 *        "role": "admin",         // Custom claim
 *        "iat": 1516239022,       // Issued At
 *        "exp": 1516242622        // Expiration
 *      }
 *
 *   3. Signature: Ensures the token hasn't been tampered with
 *      HMACSHA256(base64(header) + "." + base64(payload), secret)
 *
 * How it works:
 * 1. Client sends credentials to login endpoint.
 * 2. Server verifies credentials and creates a JWT containing user claims.
 * 3. Server signs the JWT with a secret key and returns it.
 * 4. Client stores the JWT (localStorage, cookie, etc.).
 * 5. Client sends JWT in the Authorization header: Bearer <jwt>
 * 6. Server verifies the JWT signature and reads the claims.
 * 7. No server-side session needed -- the JWT is self-contained.
 *
 * JWT vs Opaque Bearer Token:
 * - JWT is stateless -- the server doesn't need to store tokens.
 * - JWT contains claims (user info, roles, permissions) in the payload.
 * - JWT can be verified by any service that knows the secret/public key.
 * - JWT cannot be easily revoked (use short expiry + refresh tokens).
 * - Opaque tokens require a server-side lookup for every request.
 *
 * Security considerations:
 * - Never put sensitive data (passwords, secrets) in the JWT payload.
 * - Use HTTPS to prevent token interception.
 * - Keep expiration short (15-60 minutes).
 * - Use strong secrets for HMAC or RSA keys for RS256.
 * - Validate all claims (exp, iss, aud) on the server.
 *
 * Run: npm run jwt
 * ============================================================================
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3005;

app.use(express.json());

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
// In production, use a long random string stored in an environment variable.
// For RS256 (asymmetric), you would use a private key to sign and a public
// key to verify.
const JWT_SECRET = 'super-secret-jwt-key-change-in-production';
const JWT_ISSUER = 'auth-demo-server';
const JWT_EXPIRY = '1h'; // Token expires in 1 hour

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
    email: 'alice@example.com',
    role: 'admin',
    permissions: ['read', 'write', 'delete', 'manage_users'],
  });

  users.push({
    id: 2,
    username: 'bob',
    passwordHash: await bcrypt.hash('secret456', saltRounds),
    email: 'bob@example.com',
    role: 'editor',
    permissions: ['read', 'write'],
  });

  users.push({
    id: 3,
    username: 'charlie',
    passwordHash: await bcrypt.hash('test789', saltRounds),
    email: 'charlie@example.com',
    role: 'viewer',
    permissions: ['read'],
  });

  console.log('[INIT] Users initialized: alice, bob, charlie');
}

// ---------------------------------------------------------------------------
// JWT Helper Functions
// ---------------------------------------------------------------------------

/**
 * Creates a JWT for the given user.
 *
 * Standard JWT claims (registered claims):
 * - sub: Subject (user ID)
 * - iss: Issuer
 * - iat: Issued At (automatic)
 * - exp: Expiration Time
 * - jti: JWT ID (unique identifier for this token)
 *
 * Custom claims (private claims):
 * - username, email, role, permissions
 */
function createJWT(user) {
  const payload = {
    // Registered claims
    sub: user.id.toString(), // Subject: the user this token represents
    iss: JWT_ISSUER,         // Issuer: who created this token

    // Custom claims -- application-specific data
    username: user.username,
    email: user.email,
    role: user.role,
    permissions: user.permissions,
  };

  // jwt.sign() creates the token:
  // 1. Base64-encodes the header (algorithm + type)
  // 2. Base64-encodes the payload (claims)
  // 3. Creates a signature using HMAC-SHA256
  // 4. Joins them with dots: header.payload.signature
  const token = jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRY,
    algorithm: 'HS256',
  });

  return token;
}

/**
 * Decodes a JWT WITHOUT verifying the signature.
 * Useful for debugging/inspection only.
 * NEVER trust decoded data without verification.
 */
function decodeJWT(token) {
  return jwt.decode(token, { complete: true });
}

// ---------------------------------------------------------------------------
// JWT Verification Middleware
// ---------------------------------------------------------------------------
/**
 * Middleware that verifies JWT from the Authorization header.
 *
 * Steps:
 * 1. Extract the token from "Authorization: Bearer <token>".
 * 2. Verify the token's signature and claims using jwt.verify().
 * 3. If valid, attach the decoded claims to req.user.
 * 4. If invalid, return 401.
 */
function verifyJWT(req, res, next) {
  console.log(`\n[REQUEST] ${req.method} ${req.path}`);

  // Step 1: Extract the Authorization header
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    console.log('[JWT] No Authorization header');
    return res.status(401).json({
      error: 'Authentication required',
      message: 'Please provide a JWT in the Authorization header',
    });
  }

  if (!authHeader.startsWith('Bearer ')) {
    console.log('[JWT] Not a Bearer token');
    return res.status(401).json({
      error: 'Invalid scheme',
      message: 'Expected: Authorization: Bearer <jwt>',
    });
  }

  const token = authHeader.split(' ')[1];

  // Step 2: Verify the token
  try {
    // jwt.verify() does the following:
    // - Decodes the header and payload
    // - Recomputes the signature using the secret
    // - Compares it to the provided signature
    // - Checks expiration (exp claim)
    // - Checks issuer if specified
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer: JWT_ISSUER,
      algorithms: ['HS256'],
    });

    console.log(`[JWT] Valid token for user "${decoded.username}" (role: ${decoded.role})`);

    // Step 3: Attach claims to the request
    req.user = decoded;

    next();
  } catch (err) {
    // Step 4: Handle verification errors
    console.log(`[JWT] Verification failed: ${err.message}`);

    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expired',
        message: 'Your JWT has expired. Please login again.',
        expiredAt: err.expiredAt,
      });
    }

    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Invalid token',
        message: `JWT verification failed: ${err.message}`,
      });
    }

    return res.status(401).json({
      error: 'Authentication failed',
      message: err.message,
    });
  }
}

/**
 * Middleware factory to check if the user has a specific role.
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      console.log(`[AUTH] Role "${req.user.role}" not in allowed roles: [${roles.join(', ')}]`);
      return res.status(403).json({
        error: 'Forbidden',
        message: `Required role: ${roles.join(' or ')}. Your role: ${req.user.role}`,
      });
    }
    next();
  };
}

/**
 * Middleware factory to check if the user has a specific permission.
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user.permissions || !req.user.permissions.includes(permission)) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `Required permission: "${permission}". Your permissions: [${(req.user.permissions || []).join(', ')}]`,
      });
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

// Public info route
app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to the JWT Auth demo server',
    endpoints: {
      'POST /login': 'Login to receive a JWT',
      'GET /protected': 'Protected resource (any authenticated user)',
      'GET /admin': 'Admin-only resource (admin role required)',
      'POST /inspect': 'Inspect a JWT without verifying (for learning)',
      'GET /claims': 'View your JWT claims (authenticated)',
    },
    users: ['alice:password123 (admin)', 'bob:secret456 (editor)', 'charlie:test789 (viewer)'],
    jwtStructure: {
      header: '{ "alg": "HS256", "typ": "JWT" }',
      payload: '{ sub, username, email, role, permissions, iat, exp, iss }',
      signature: 'HMACSHA256(base64(header) + "." + base64(payload), secret)',
    },
  });
});

/**
 * Login endpoint.
 * Validates credentials and returns a JWT.
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

  // Find user
  const user = users.find((u) => u.username === username);

  if (!user) {
    return res.status(401).json({
      error: 'Invalid credentials',
      message: 'Username or password is incorrect',
    });
  }

  // Verify password
  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

  if (!isPasswordValid) {
    return res.status(401).json({
      error: 'Invalid credentials',
      message: 'Username or password is incorrect',
    });
  }

  // Create JWT
  const token = createJWT(user);

  // Decode the token to show its structure (for educational purposes)
  const decoded = decodeJWT(token);

  console.log(`[LOGIN] JWT created for user "${username}"`);
  console.log(`[LOGIN] Token expires: ${new Date(decoded.payload.exp * 1000).toISOString()}`);

  res.json({
    message: 'Login successful',
    token: token,
    tokenType: 'Bearer',
    expiresIn: JWT_EXPIRY,
    // Show the JWT structure for educational purposes
    jwtStructure: {
      header: decoded.header,
      payload: decoded.payload,
      note: 'The signature is the third part of the token (after the second dot)',
    },
    usage: `Authorization: Bearer ${token}`,
  });
});

/**
 * Inspect a JWT without verifying.
 * This shows the token's structure and claims.
 * Body: { "token": "<jwt>" }
 */
app.post('/inspect', (req, res) => {
  console.log('\n[REQUEST] POST /inspect');

  const { token } = req.body;

  if (!token) {
    return res.status(400).json({
      error: 'Bad request',
      message: 'Provide a "token" field in the request body',
    });
  }

  // Split the token to show its three parts
  const parts = token.split('.');

  if (parts.length !== 3) {
    return res.status(400).json({
      error: 'Invalid JWT format',
      message: 'A JWT must have exactly 3 parts separated by dots',
    });
  }

  // Decode without verification (for inspection only)
  const decoded = decodeJWT(token);

  res.json({
    message: 'JWT inspection (NOT verified -- do not trust this data)',
    warning: 'This decodes the token WITHOUT verifying the signature!',
    rawParts: {
      header: parts[0],
      payload: parts[1],
      signature: parts[2],
    },
    decoded: {
      header: decoded.header,
      payload: decoded.payload,
    },
    timing: decoded.payload.exp
      ? {
          issuedAt: new Date(decoded.payload.iat * 1000).toISOString(),
          expiresAt: new Date(decoded.payload.exp * 1000).toISOString(),
          isExpired: Date.now() > decoded.payload.exp * 1000,
        }
      : 'No expiration set',
  });
});

// Protected route (any authenticated user)
app.get('/protected', verifyJWT, (req, res) => {
  console.log(`[RESPONSE] Protected resource for ${req.user.username}`);
  res.json({
    message: 'You have accessed a protected resource!',
    user: {
      id: req.user.sub,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role,
    },
    tokenInfo: {
      issuedAt: new Date(req.user.iat * 1000).toISOString(),
      expiresAt: new Date(req.user.exp * 1000).toISOString(),
      issuer: req.user.iss,
    },
  });
});

// View all claims from your JWT
app.get('/claims', verifyJWT, (req, res) => {
  console.log(`[RESPONSE] Claims for ${req.user.username}`);
  res.json({
    message: 'Your JWT claims',
    claims: req.user,
    explanation: {
      sub: 'Subject -- who this token represents (user ID)',
      iss: 'Issuer -- who created this token',
      iat: 'Issued At -- when the token was created (Unix timestamp)',
      exp: 'Expiration -- when the token expires (Unix timestamp)',
      username: 'Custom claim -- the user\'s username',
      email: 'Custom claim -- the user\'s email',
      role: 'Custom claim -- the user\'s role',
      permissions: 'Custom claim -- the user\'s permissions array',
    },
  });
});

// Admin-only route
app.get('/admin', verifyJWT, requireRole('admin'), (req, res) => {
  console.log(`[RESPONSE] Admin resource for ${req.user.username}`);
  res.json({
    message: 'Welcome to the admin panel!',
    user: req.user.username,
    allUsers: users.map((u) => ({
      id: u.id,
      username: u.username,
      role: u.role,
    })),
  });
});

// Write-protected route
app.post('/articles', verifyJWT, requirePermission('write'), (req, res) => {
  console.log(`[RESPONSE] Article creation by ${req.user.username}`);
  res.status(201).json({
    message: 'Article created',
    author: req.user.username,
    article: req.body,
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
    console.log(`  JWT Auth Server running on port ${PORT}`);
    console.log(`========================================`);
    console.log(`\nTest commands:`);
    console.log(`  # Login to get a JWT:`);
    console.log(`  curl -X POST http://localhost:${PORT}/login \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"username":"alice","password":"password123"}'`);
    console.log(`\n  # Access protected resource:`);
    console.log(`  curl http://localhost:${PORT}/protected \\`);
    console.log(`    -H "Authorization: Bearer <YOUR_JWT>"`);
    console.log(`\n  # Inspect a JWT:`);
    console.log(`  curl -X POST http://localhost:${PORT}/inspect \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"token":"<YOUR_JWT>"}'`);
  });
});
