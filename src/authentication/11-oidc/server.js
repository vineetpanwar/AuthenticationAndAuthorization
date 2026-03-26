/**
 * ============================================================================
 * OpenID Connect (OIDC) SSO Simulation
 * ============================================================================
 *
 * What is OIDC?
 * -------------
 * OpenID Connect 1.0 is an identity layer built ON TOP of OAuth 2.0.
 * While OAuth 2.0 only handles authorization ("what can this app do?"),
 * OIDC adds authentication ("who is this user?") via ID tokens.
 *
 * Key Concepts:
 * - OP (OpenID Provider): The identity server (e.g., Google, Auth0, Okta)
 * - RP (Relying Party): The application that wants to authenticate users
 * - ID Token: A JWT containing the user's identity claims (sub, email, name, etc.)
 * - Access Token: Grants access to the UserInfo endpoint (or APIs)
 * - UserInfo Endpoint: Returns additional user claims
 * - Discovery: /.well-known/openid-configuration provides all endpoint URLs
 * - Scopes: openid (required), profile, email, address, phone
 *
 * OIDC Authorization Code Flow:
 * 1. RP redirects user to OP's /authorize endpoint (with scope=openid)
 * 2. User authenticates at the OP
 * 3. OP redirects back to RP with an authorization code
 * 4. RP exchanges code for tokens at OP's /token endpoint
 * 5. RP receives: ID Token (JWT) + Access Token + (optional) Refresh Token
 * 6. RP validates the ID Token signature and claims
 * 7. RP can call /userinfo for additional claims
 *
 * OIDC vs SAML:
 * - OIDC uses JSON/JWT; SAML uses XML
 * - OIDC is simpler and more developer-friendly
 * - SAML is dominant in enterprise; OIDC is dominant in consumer/modern apps
 * - OIDC natively supports mobile and SPA; SAML is browser-only
 *
 * Run: npm run oidc
 * ============================================================================
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
const PORT = 3014;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const ISSUER = 'http://localhost:3014';
const SIGNING_KEY = 'oidc-signing-key-simulates-rsa-private-key';
const ID_TOKEN_EXPIRY = '1h';
const ACCESS_TOKEN_EXPIRY = '15m';
const AUTH_CODE_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes

// ---------------------------------------------------------------------------
// User Store
// ---------------------------------------------------------------------------
const users = [];

async function initializeUsers() {
  users.push({
    sub: 'user-001',
    username: 'alice',
    passwordHash: await bcrypt.hash('password123', 10),
    email: 'alice@company.com',
    email_verified: true,
    name: 'Alice Johnson',
    given_name: 'Alice',
    family_name: 'Johnson',
    picture: 'https://example.com/alice.jpg',
    locale: 'en-US',
    zoneinfo: 'America/New_York',
  });
  users.push({
    sub: 'user-002',
    username: 'bob',
    passwordHash: await bcrypt.hash('secret456', 10),
    email: 'bob@company.com',
    email_verified: true,
    name: 'Bob Smith',
    given_name: 'Bob',
    family_name: 'Smith',
    picture: 'https://example.com/bob.jpg',
    locale: 'en-US',
    zoneinfo: 'America/Chicago',
  });
  console.log('[OP] Users initialized: alice:password123, bob:secret456');
}

// ---------------------------------------------------------------------------
// Registered Clients (Relying Parties)
// ---------------------------------------------------------------------------
const clients = {
  'app-dashboard': {
    client_id: 'app-dashboard',
    client_secret: 'dashboard-secret-123',
    name: 'Dashboard App',
    redirect_uris: ['http://localhost:3014/callback/app-dashboard'],
    grant_types: ['authorization_code'],
    scopes: ['openid', 'profile', 'email'],
  },
  'app-mobile': {
    client_id: 'app-mobile',
    client_secret: 'mobile-secret-456',
    name: 'Mobile App',
    redirect_uris: ['http://localhost:3014/callback/app-mobile'],
    grant_types: ['authorization_code'],
    scopes: ['openid', 'profile', 'email'],
  },
};

// ---------------------------------------------------------------------------
// Stores
// ---------------------------------------------------------------------------
const authCodes = new Map();    // code -> { clientId, userId, scopes, nonce, codeChallenge, redirectUri, createdAt }
const accessTokens = new Map(); // token -> { sub, clientId, scopes }
const opSessions = new Map();   // sessionId -> { sub, username, authenticatedAt }

// ---------------------------------------------------------------------------
// OIDC Discovery Endpoint
// ---------------------------------------------------------------------------
app.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    userinfo_endpoint: `${ISSUER}/userinfo`,
    jwks_uri: `${ISSUER}/jwks`,
    end_session_endpoint: `${ISSUER}/logout`,
    scopes_supported: ['openid', 'profile', 'email'],
    response_types_supported: ['code', 'id_token', 'code id_token'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256', 'HS256'],
    token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'email', 'email_verified', 'name', 'given_name', 'family_name', 'picture', 'locale'],
  });
});

// JWKS (JSON Web Key Set) -- in production, this would contain the RSA public key
app.get('/jwks', (req, res) => {
  res.json({
    keys: [
      {
        kty: 'oct',
        kid: 'oidc-demo-key-1',
        use: 'sig',
        alg: 'HS256',
        note: 'In production this would be an RSA public key (kty: RSA) so RPs can verify ID tokens without the secret',
      },
    ],
  });
});

// ---------------------------------------------------------------------------
// Authorization Endpoint
// ---------------------------------------------------------------------------
app.get('/authorize', (req, res) => {
  const { client_id, redirect_uri, response_type, scope, state, nonce, code_challenge, code_challenge_method } = req.query;

  console.log(`\n[OP] === Authorization Request ===`);
  console.log(`[OP] client_id: ${client_id}, scope: ${scope}`);

  const client = clients[client_id];
  if (!client) return res.status(400).json({ error: 'invalid_client', message: 'Unknown client_id' });

  if (response_type !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type' });
  }

  // In a real OP, this would render a login page.
  // Here we return instructions to POST credentials.
  res.json({
    step: '1 of 5 — Authorization Request received',
    message: 'In a real OIDC flow, you would see a login page here.',
    description: 'The RP redirected you to the OP with these parameters:',
    request: { client_id, redirect_uri, response_type, scope, state, nonce },
    nextStep: {
      description: 'Authenticate by POSTing your credentials',
      url: '/authorize/login',
      body: {
        username: '<username>',
        password: '<password>',
        client_id,
        redirect_uri: redirect_uri || client.redirect_uris[0],
        scope: scope || 'openid profile email',
        state: state || 'random-state-value',
        nonce: nonce || 'random-nonce-value',
        code_challenge,
        code_challenge_method,
      },
    },
  });
});

// Authenticate and issue authorization code
app.post('/authorize/login', async (req, res) => {
  const { username, password, client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method } = req.body;

  console.log(`\n[OP] Login attempt: ${username} for client ${client_id}`);

  const client = clients[client_id];
  if (!client) return res.status(400).json({ error: 'invalid_client' });

  // Authenticate
  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'access_denied', message: 'Invalid credentials' });
  }

  console.log(`[OP] User "${username}" authenticated`);

  // Create OP session
  const sessionId = uuidv4();
  opSessions.set(sessionId, { sub: user.sub, username: user.username, authenticatedAt: new Date().toISOString() });

  // Generate authorization code
  const code = crypto.randomBytes(32).toString('hex');
  authCodes.set(code, {
    clientId: client_id,
    userId: user.sub,
    scopes: (scope || 'openid').split(' '),
    nonce,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    redirectUri: redirect_uri || client.redirect_uris[0],
    createdAt: Date.now(),
  });

  const callbackUrl = `${redirect_uri || client.redirect_uris[0]}?code=${code}&state=${state || ''}`;

  res.json({
    step: '2 of 5 — User authenticated, authorization code issued',
    message: 'In a real flow, you would be redirected to the callback URL below.',
    callbackUrl,
    code,
    state,
    nextStep: {
      description: 'Exchange the authorization code for tokens at the token endpoint',
      url: '/token',
      body: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirect_uri || client.redirect_uris[0],
        client_id,
        client_secret: client.client_secret,
      },
    },
  });
});

// ---------------------------------------------------------------------------
// Token Endpoint
// ---------------------------------------------------------------------------
app.post('/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;

  console.log(`\n[OP] === Token Request ===`);

  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  // Validate client credentials
  const client = clients[client_id];
  if (!client || client.client_secret !== client_secret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  // Validate authorization code
  const codeData = authCodes.get(code);
  if (!codeData) return res.status(400).json({ error: 'invalid_grant', message: 'Code expired or invalid' });

  if (codeData.clientId !== client_id) {
    return res.status(400).json({ error: 'invalid_grant', message: 'Code was not issued to this client' });
  }

  if (Date.now() - codeData.createdAt > AUTH_CODE_EXPIRY_MS) {
    authCodes.delete(code);
    return res.status(400).json({ error: 'invalid_grant', message: 'Code expired' });
  }

  // One-time use
  authCodes.delete(code);

  // Find user
  const user = users.find(u => u.sub === codeData.userId);
  if (!user) return res.status(500).json({ error: 'server_error' });

  // Build ID Token claims based on requested scopes
  const idTokenClaims = {
    iss: ISSUER,
    sub: user.sub,
    aud: client_id,
    iat: Math.floor(Date.now() / 1000),
    auth_time: Math.floor(Date.now() / 1000),
  };

  if (codeData.nonce) idTokenClaims.nonce = codeData.nonce;

  if (codeData.scopes.includes('email')) {
    idTokenClaims.email = user.email;
    idTokenClaims.email_verified = user.email_verified;
  }

  if (codeData.scopes.includes('profile')) {
    idTokenClaims.name = user.name;
    idTokenClaims.given_name = user.given_name;
    idTokenClaims.family_name = user.family_name;
    idTokenClaims.picture = user.picture;
    idTokenClaims.locale = user.locale;
  }

  const idToken = jwt.sign(idTokenClaims, SIGNING_KEY, { expiresIn: ID_TOKEN_EXPIRY });
  const accessToken = crypto.randomBytes(32).toString('hex');

  accessTokens.set(accessToken, {
    sub: user.sub,
    clientId: client_id,
    scopes: codeData.scopes,
    createdAt: Date.now(),
  });

  console.log(`[OP] Tokens issued for "${user.username}"`);

  res.json({
    step: '3 of 5 — Authorization code exchanged for tokens',
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 900,
    id_token: idToken,
    scope: codeData.scopes.join(' '),
    decodedIdToken: idTokenClaims,
    nextSteps: {
      validateIdToken: 'The RP should validate the ID Token: verify signature, check iss, aud, exp, nonce',
      getUserInfo: {
        description: 'Optionally call /userinfo for more claims',
        url: '/userinfo',
        headers: { Authorization: `Bearer ${accessToken}` },
      },
    },
  });
});

// ---------------------------------------------------------------------------
// UserInfo Endpoint
// ---------------------------------------------------------------------------
app.get('/userinfo', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const tokenData = accessTokens.get(token);
  if (!tokenData) return res.status(401).json({ error: 'invalid_token' });

  const user = users.find(u => u.sub === tokenData.sub);
  if (!user) return res.status(500).json({ error: 'server_error' });

  const claims = { sub: user.sub };
  if (tokenData.scopes.includes('email')) {
    claims.email = user.email;
    claims.email_verified = user.email_verified;
  }
  if (tokenData.scopes.includes('profile')) {
    claims.name = user.name;
    claims.given_name = user.given_name;
    claims.family_name = user.family_name;
    claims.picture = user.picture;
    claims.locale = user.locale;
    claims.zoneinfo = user.zoneinfo;
  }

  res.json(claims);
});

// Callback endpoints (simulates RP receiving the code)
app.get('/callback/:clientId', (req, res) => {
  const { code, state } = req.query;
  res.json({
    step: 'RP Callback — received authorization code',
    message: 'In a real app, the RP backend would now exchange this code for tokens',
    code,
    state,
    nextStep: {
      url: '/token',
      body: {
        grant_type: 'authorization_code',
        code,
        redirect_uri: `http://localhost:${PORT}/callback/${req.params.clientId}`,
        client_id: req.params.clientId,
        client_secret: clients[req.params.clientId]?.client_secret,
      },
    },
  });
});

// Logout
app.post('/logout', (req, res) => {
  const { id_token_hint, client_id } = req.body;
  // In real OIDC, the OP would invalidate the session and optionally notify RPs via backchannel logout
  if (id_token_hint) {
    try {
      const decoded = jwt.verify(id_token_hint, SIGNING_KEY);
      for (const [sid, sess] of opSessions) {
        if (sess.sub === decoded.sub) opSessions.delete(sid);
      }
      res.json({ message: `Logged out user ${decoded.sub}` });
    } catch {
      res.status(400).json({ error: 'Invalid id_token_hint' });
    }
  } else {
    res.json({ message: 'Provide id_token_hint to identify the session to terminate' });
  }
});

// ---------------------------------------------------------------------------
// Info Route
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
  res.json({
    message: 'OpenID Connect (OIDC) SSO Simulation',
    protocol: 'OpenID Connect 1.0 (built on OAuth 2.0)',
    description: 'JSON/JWT-based identity protocol for modern SSO',
    discovery: '/.well-known/openid-configuration',
    flow: [
      '1. GET /authorize?client_id=app-dashboard&response_type=code&scope=openid profile email&state=xyz&nonce=abc',
      '2. POST /authorize/login (authenticate at OP)',
      '3. POST /token (exchange code for ID Token + Access Token)',
      '4. GET /userinfo (optional: get additional claims)',
    ],
    registeredClients: Object.values(clients).map(c => ({
      client_id: c.client_id, name: c.name, scopes: c.scopes,
    })),
    comparisonToSAML: {
      format: 'JSON/JWT (vs XML)',
      complexity: 'Lower (vs higher for SAML)',
      mobileSupport: 'Native (vs browser-only for SAML)',
      adoption: 'Consumer + modern enterprise (vs legacy enterprise for SAML)',
    },
  });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------
app.use((err, req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: err.message });
});

initializeUsers().then(() => {
  app.listen(PORT, () => {
    console.log(`\n========================================`);
    console.log(`  OIDC SSO Server running on port ${PORT}`);
    console.log(`========================================`);
    console.log(`\nDiscovery: http://localhost:${PORT}/.well-known/openid-configuration`);
    console.log(`\nTest the full OIDC Authorization Code flow:`);
    console.log(`\n  # Step 1: Start authorization`);
    console.log(`  curl "http://localhost:${PORT}/authorize?client_id=app-dashboard&response_type=code&scope=openid+profile+email&state=xyz123&nonce=abc456"`);
    console.log(`\n  # Step 2: Login`);
    console.log(`  curl -X POST http://localhost:${PORT}/authorize/login \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"username":"alice","password":"password123","client_id":"app-dashboard","scope":"openid profile email","state":"xyz123","nonce":"abc456"}'`);
    console.log(`\n  # Step 3: Exchange code for tokens`);
    console.log(`  curl -X POST http://localhost:${PORT}/token \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"grant_type":"authorization_code","code":"<CODE>","client_id":"app-dashboard","client_secret":"dashboard-secret-123"}'`);
    console.log(`\n  # Step 4: Get user info`);
    console.log(`  curl http://localhost:${PORT}/userinfo -H "Authorization: Bearer <ACCESS_TOKEN>"`);
  });
});
