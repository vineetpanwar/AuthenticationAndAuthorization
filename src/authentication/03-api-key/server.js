/**
 * ============================================================================
 * API KEY AUTHENTICATION
 * ============================================================================
 *
 * What is API Key Auth?
 * ---------------------
 * API Key authentication uses a unique, pre-shared key to identify and
 * authenticate a client. The key is typically sent in a custom HTTP header
 * (e.g., X-API-Key), a query parameter, or sometimes in the request body.
 *
 * How it works:
 * 1. A client registers and receives an API key.
 * 2. The client includes the API key in every request.
 * 3. The server validates the key and identifies the client.
 * 4. The server may enforce rate limits and permission tiers per key.
 *
 * Common use cases:
 * - Public APIs (Google Maps, OpenWeatherMap, Stripe, etc.)
 * - Server-to-server communication
 * - Third-party integrations
 *
 * Security considerations:
 * - API keys identify the calling application, not necessarily the user.
 * - Keys should be transmitted over HTTPS only.
 * - Implement rate limiting to prevent abuse.
 * - Use different permission tiers to control access levels.
 * - Allow key rotation and revocation.
 * - Never expose API keys in client-side code or URLs where possible.
 *
 * API Key vs Bearer Token:
 * - API keys are long-lived and identify an application/client.
 * - Bearer tokens are often short-lived and identify a user session.
 * - API keys are typically provisioned manually; bearer tokens via login.
 *
 * Run: npm run api-key
 * ============================================================================
 */

const express = require('express');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3003;

app.use(express.json());

// ---------------------------------------------------------------------------
// API Key store (in-memory Map)
// Maps: apiKey (string) -> { owner, tier, createdAt, permissions, rateLimit }
//
// In production, store API keys hashed (like passwords) in a database.
// ---------------------------------------------------------------------------
const apiKeyStore = new Map();

// ---------------------------------------------------------------------------
// Rate limiting store
// Maps: apiKey (string) -> { count, windowStart }
// ---------------------------------------------------------------------------
const rateLimitStore = new Map();

// Rate limit windows (requests per minute) by tier
const RATE_LIMITS = {
  free: 10,        // 10 requests per minute
  pro: 100,        // 100 requests per minute
  enterprise: 1000, // 1000 requests per minute
};

// Rate limit window duration (1 minute in milliseconds)
const RATE_LIMIT_WINDOW_MS = 60 * 1000;

// ---------------------------------------------------------------------------
// Tier-based permissions
// Each tier has access to different sets of endpoints/features.
// ---------------------------------------------------------------------------
const TIER_PERMISSIONS = {
  free: ['read'],
  pro: ['read', 'write'],
  enterprise: ['read', 'write', 'admin', 'bulk'],
};

// ---------------------------------------------------------------------------
// Seed some initial API keys for demonstration
// ---------------------------------------------------------------------------
function initializeApiKeys() {
  const keys = [
    {
      key: 'free-demo-key-12345',
      owner: 'Demo Free User',
      tier: 'free',
    },
    {
      key: 'pro-demo-key-67890',
      owner: 'Demo Pro User',
      tier: 'pro',
    },
    {
      key: 'enterprise-demo-key-11111',
      owner: 'Demo Enterprise User',
      tier: 'enterprise',
    },
  ];

  for (const k of keys) {
    apiKeyStore.set(k.key, {
      owner: k.owner,
      tier: k.tier,
      permissions: TIER_PERMISSIONS[k.tier],
      createdAt: new Date().toISOString(),
      isActive: true,
    });
  }

  console.log('[INIT] Demo API keys created:');
  console.log('  Free tier:       free-demo-key-12345');
  console.log('  Pro tier:        pro-demo-key-67890');
  console.log('  Enterprise tier: enterprise-demo-key-11111');
}

// ---------------------------------------------------------------------------
// Rate Limiting Logic
// ---------------------------------------------------------------------------
/**
 * Checks and enforces rate limits for a given API key.
 * Uses a sliding window approach (resets after RATE_LIMIT_WINDOW_MS).
 *
 * Returns: { allowed: boolean, remaining: number, resetAt: Date }
 */
function checkRateLimit(apiKey, tier) {
  const now = Date.now();
  const maxRequests = RATE_LIMITS[tier] || RATE_LIMITS.free;

  let rateLimitData = rateLimitStore.get(apiKey);

  // If no existing data or window has expired, start a new window
  if (!rateLimitData || now - rateLimitData.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateLimitData = {
      count: 0,
      windowStart: now,
    };
  }

  rateLimitData.count += 1;
  rateLimitStore.set(apiKey, rateLimitData);

  const remaining = Math.max(0, maxRequests - rateLimitData.count);
  const resetAt = new Date(rateLimitData.windowStart + RATE_LIMIT_WINDOW_MS);

  return {
    allowed: rateLimitData.count <= maxRequests,
    remaining,
    limit: maxRequests,
    resetAt: resetAt.toISOString(),
  };
}

// ---------------------------------------------------------------------------
// API Key Middleware
// ---------------------------------------------------------------------------
/**
 * Middleware that validates API keys.
 *
 * The API key can be provided in:
 * 1. X-API-Key header (preferred)
 * 2. ?api_key= query parameter (less secure, may appear in logs)
 *
 * Steps:
 * 1. Extract the API key from the header or query parameter.
 * 2. Look up the key in the store.
 * 3. Check if the key is active.
 * 4. Enforce rate limits.
 * 5. Attach client info to req.apiClient.
 */
function apiKeyMiddleware(req, res, next) {
  console.log(`\n[REQUEST] ${req.method} ${req.path}`);

  // Step 1: Extract API key from header or query parameter
  const apiKey = req.headers['x-api-key'] || req.query.api_key;

  if (!apiKey) {
    console.log('[AUTH] No API key provided');
    return res.status(401).json({
      error: 'API key required',
      message: 'Provide your API key via X-API-Key header or ?api_key= query parameter',
    });
  }

  // Step 2: Look up the key
  const keyData = apiKeyStore.get(apiKey);

  if (!keyData) {
    console.log(`[AUTH] Invalid API key: ${apiKey.substring(0, 8)}...`);
    return res.status(401).json({
      error: 'Invalid API key',
      message: 'The provided API key is not recognized',
    });
  }

  // Step 3: Check if the key is active
  if (!keyData.isActive) {
    console.log(`[AUTH] Revoked API key used by "${keyData.owner}"`);
    return res.status(403).json({
      error: 'API key revoked',
      message: 'This API key has been revoked. Please generate a new one.',
    });
  }

  // Step 4: Enforce rate limits
  const rateLimit = checkRateLimit(apiKey, keyData.tier);

  // Set rate limit headers (following standard conventions)
  res.set('X-RateLimit-Limit', rateLimit.limit.toString());
  res.set('X-RateLimit-Remaining', rateLimit.remaining.toString());
  res.set('X-RateLimit-Reset', rateLimit.resetAt);

  if (!rateLimit.allowed) {
    console.log(`[RATE LIMIT] Exceeded for "${keyData.owner}" (${keyData.tier} tier)`);
    return res.status(429).json({
      error: 'Rate limit exceeded',
      message: `You have exceeded the ${RATE_LIMITS[keyData.tier]} requests/minute limit for the ${keyData.tier} tier`,
      retryAfter: rateLimit.resetAt,
    });
  }

  console.log(`[AUTH] Valid API key for "${keyData.owner}" (${keyData.tier} tier, ${rateLimit.remaining} remaining)`);

  // Step 5: Attach client info to the request
  req.apiClient = {
    owner: keyData.owner,
    tier: keyData.tier,
    permissions: keyData.permissions,
  };

  next();
}

// ---------------------------------------------------------------------------
// Permission-checking middleware factory
// ---------------------------------------------------------------------------
/**
 * Returns middleware that checks if the API key's tier has the required
 * permission.
 *
 * Usage: app.post('/data', apiKeyMiddleware, requirePermission('write'), handler)
 */
function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.apiClient.permissions.includes(permission)) {
      console.log(`[PERMISSION] Denied "${permission}" for ${req.apiClient.owner} (${req.apiClient.tier} tier)`);
      return res.status(403).json({
        error: 'Insufficient permissions',
        message: `Your ${req.apiClient.tier} tier does not include "${permission}" permission`,
        requiredPermission: permission,
        yourPermissions: req.apiClient.permissions,
        upgradeTip: 'Upgrade your tier for additional permissions',
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
    message: 'Welcome to the API Key Auth demo server',
    endpoints: {
      'POST /api-keys': 'Generate a new API key (provide owner and tier)',
      'GET /data': 'Read data (requires "read" permission -- all tiers)',
      'POST /data': 'Write data (requires "write" permission -- pro & enterprise)',
      'DELETE /data/:id': 'Delete data (requires "admin" permission -- enterprise only)',
      'POST /data/bulk': 'Bulk import (requires "bulk" permission -- enterprise only)',
      'GET /usage': 'View your rate limit usage',
      'DELETE /api-keys/:key': 'Revoke an API key',
    },
    demoKeys: {
      free: 'free-demo-key-12345',
      pro: 'pro-demo-key-67890',
      enterprise: 'enterprise-demo-key-11111',
    },
  });
});

/**
 * API key generation endpoint.
 * In production, this would require admin authentication.
 *
 * Body: { "owner": "Company Name", "tier": "free|pro|enterprise" }
 */
app.post('/api-keys', (req, res) => {
  console.log('\n[REQUEST] POST /api-keys');

  const { owner, tier } = req.body;

  if (!owner) {
    return res.status(400).json({
      error: 'Bad request',
      message: 'Owner name is required',
    });
  }

  const validTiers = ['free', 'pro', 'enterprise'];
  const selectedTier = validTiers.includes(tier) ? tier : 'free';

  // Generate a unique API key
  const newKey = `${selectedTier}-${uuidv4()}`;

  apiKeyStore.set(newKey, {
    owner,
    tier: selectedTier,
    permissions: TIER_PERMISSIONS[selectedTier],
    createdAt: new Date().toISOString(),
    isActive: true,
  });

  console.log(`[API KEY] Generated ${selectedTier} key for "${owner}"`);

  res.status(201).json({
    message: 'API key generated successfully',
    apiKey: newKey,
    tier: selectedTier,
    permissions: TIER_PERMISSIONS[selectedTier],
    rateLimit: `${RATE_LIMITS[selectedTier]} requests/minute`,
    warning: 'Store this key securely. It will not be shown again.',
  });
});

// Read data (all tiers)
app.get('/data', apiKeyMiddleware, requirePermission('read'), (req, res) => {
  console.log(`[RESPONSE] Serving data for ${req.apiClient.owner}`);
  res.json({
    message: 'Here is your data',
    data: [
      { id: 1, name: 'Item A', value: 100 },
      { id: 2, name: 'Item B', value: 200 },
      { id: 3, name: 'Item C', value: 300 },
    ],
    client: req.apiClient,
  });
});

// Write data (pro and enterprise only)
app.post('/data', apiKeyMiddleware, requirePermission('write'), (req, res) => {
  console.log(`[RESPONSE] Write operation by ${req.apiClient.owner}`);
  res.status(201).json({
    message: 'Data created successfully',
    created: req.body,
    client: req.apiClient,
  });
});

// Delete data (enterprise only)
app.delete('/data/:id', apiKeyMiddleware, requirePermission('admin'), (req, res) => {
  console.log(`[RESPONSE] Delete operation by ${req.apiClient.owner}`);
  res.json({
    message: `Data item ${req.params.id} deleted successfully`,
    client: req.apiClient,
  });
});

// Bulk import (enterprise only)
app.post('/data/bulk', apiKeyMiddleware, requirePermission('bulk'), (req, res) => {
  console.log(`[RESPONSE] Bulk operation by ${req.apiClient.owner}`);
  res.json({
    message: 'Bulk import completed',
    itemsProcessed: Array.isArray(req.body.items) ? req.body.items.length : 0,
    client: req.apiClient,
  });
});

// View rate limit usage
app.get('/usage', apiKeyMiddleware, (req, res) => {
  res.json({
    client: req.apiClient,
    rateLimit: {
      limit: RATE_LIMITS[req.apiClient.tier],
      window: '1 minute',
    },
    headers: {
      'X-RateLimit-Limit': 'Max requests per window',
      'X-RateLimit-Remaining': 'Requests left in current window',
      'X-RateLimit-Reset': 'When the current window resets',
    },
  });
});

// Revoke an API key
app.delete('/api-keys/:key', (req, res) => {
  console.log('\n[REQUEST] DELETE /api-keys/:key');

  const keyData = apiKeyStore.get(req.params.key);

  if (!keyData) {
    return res.status(404).json({
      error: 'Not found',
      message: 'API key not found',
    });
  }

  // Mark as inactive rather than deleting (for audit trail)
  keyData.isActive = false;
  keyData.revokedAt = new Date().toISOString();
  apiKeyStore.set(req.params.key, keyData);

  console.log(`[API KEY] Revoked key for "${keyData.owner}"`);

  res.json({
    message: 'API key revoked successfully',
    owner: keyData.owner,
    revokedAt: keyData.revokedAt,
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
initializeApiKeys();

app.listen(PORT, () => {
  console.log(`\n========================================`);
  console.log(`  API Key Auth Server running on port ${PORT}`);
  console.log(`========================================`);
  console.log(`\nTest commands:`);
  console.log(`  # Read data (free tier):`);
  console.log(`  curl http://localhost:${PORT}/data \\`);
  console.log(`    -H "X-API-Key: free-demo-key-12345"`);
  console.log(`\n  # Write data (pro tier):`);
  console.log(`  curl -X POST http://localhost:${PORT}/data \\`);
  console.log(`    -H "X-API-Key: pro-demo-key-67890" \\`);
  console.log(`    -H "Content-Type: application/json" \\`);
  console.log(`    -d '{"name":"New Item","value":999}'`);
  console.log(`\n  # Try write with free tier (will be 403):`);
  console.log(`  curl -X POST http://localhost:${PORT}/data \\`);
  console.log(`    -H "X-API-Key: free-demo-key-12345" \\`);
  console.log(`    -H "Content-Type: application/json" \\`);
  console.log(`    -d '{"name":"Test"}'`);
  console.log(`\n  # Generate a new API key:`);
  console.log(`  curl -X POST http://localhost:${PORT}/api-keys \\`);
  console.log(`    -H "Content-Type: application/json" \\`);
  console.log(`    -d '{"owner":"My App","tier":"pro"}'`);
});
