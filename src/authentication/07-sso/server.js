/**
 * ============================================================================
 * SINGLE SIGN-ON (SSO) SIMULATION
 * ============================================================================
 *
 * What is SSO?
 * ------------
 * Single Sign-On (SSO) allows a user to authenticate once with an Identity
 * Provider (IdP) and gain access to multiple independent applications
 * (Service Providers / SPs) without re-entering credentials.
 *
 * Real-world examples:
 * - Login to Google once -> access Gmail, Drive, YouTube, Calendar, etc.
 * - Login via corporate Okta/Azure AD -> access Slack, Jira, GitHub, etc.
 *
 * SSO Protocols:
 * ---------------
 *
 * SAML 2.0 (Security Assertion Markup Language):
 * - XML-based protocol, primarily for enterprise SSO.
 * - Uses XML "assertions" (signed statements about the user).
 * - Browser-based flow using HTTP POST or redirects.
 * - The IdP sends a signed SAML assertion to the SP.
 * - Mature and widely used in enterprise environments.
 * - Flow:
 *   1. User visits SP (e.g., Jira).
 *   2. SP redirects to IdP (e.g., Okta) with a SAML AuthnRequest.
 *   3. User authenticates at IdP.
 *   4. IdP sends a signed SAML Response/Assertion to SP's ACS URL.
 *   5. SP validates the assertion's signature, extracts user info.
 *   6. SP creates a local session.
 *
 * OAuth 2.0 / OpenID Connect (OIDC):
 * - JSON-based protocol, used for both consumer and enterprise SSO.
 * - OIDC is a layer on top of OAuth 2.0 that adds identity (ID tokens).
 * - Uses JWT tokens rather than XML assertions.
 * - More modern and developer-friendly than SAML.
 * - Flow:
 *   1. User visits SP.
 *   2. SP redirects to IdP's authorization endpoint.
 *   3. User authenticates at IdP.
 *   4. IdP redirects back with an authorization code.
 *   5. SP exchanges code for ID token + access token.
 *   6. SP reads user info from the ID token (JWT).
 *
 * This Simulation:
 * ----------------
 * This server simulates BOTH an Identity Provider (IdP) and multiple
 * Service Providers (SPs) to demonstrate the SSO flow. In production,
 * these would be separate services.
 *
 * We simulate a SAML-like flow (simplified):
 * - IdP authenticates the user and issues signed assertions.
 * - SPs trust the IdP and create local sessions from assertions.
 * - A shared session allows access to multiple services.
 *
 * Run: npm run sso
 * ============================================================================
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3007;

app.use(express.json());

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
// The IdP uses this secret to sign assertions.
// In real SAML, this would be an X.509 certificate/private key.
const IDP_SIGNING_SECRET = 'idp-signing-secret-simulates-x509-certificate';
const ASSERTION_EXPIRY = '5m'; // SAML assertions are typically very short-lived

// ---------------------------------------------------------------------------
// Identity Provider (IdP) -- User Store
// ---------------------------------------------------------------------------
const idpUsers = [];

async function initializeUsers() {
  const saltRounds = 10;

  idpUsers.push({
    id: 'user-001',
    username: 'alice',
    passwordHash: await bcrypt.hash('password123', saltRounds),
    email: 'alice@company.com',
    displayName: 'Alice Johnson',
    department: 'Engineering',
    groups: ['engineering', 'admin'],
  });

  idpUsers.push({
    id: 'user-002',
    username: 'bob',
    passwordHash: await bcrypt.hash('secret456', saltRounds),
    email: 'bob@company.com',
    displayName: 'Bob Smith',
    department: 'Marketing',
    groups: ['marketing'],
  });

  console.log('[IdP] Users initialized: alice:password123, bob:secret456');
}

// ---------------------------------------------------------------------------
// Identity Provider (IdP) -- Session Store
// Tracks users who have authenticated with the IdP.
// ---------------------------------------------------------------------------
const idpSessions = new Map(); // sessionId -> { userId, username, authenticatedAt }

// ---------------------------------------------------------------------------
// Service Provider (SP) -- Session Stores
// Each service has its own session store. In SSO, the user authenticates
// once with the IdP and gets sessions in each SP automatically.
// ---------------------------------------------------------------------------
const services = {
  'email-app': {
    name: 'Email Application',
    sessions: new Map(), // sessionToken -> { userId, username, ... }
  },
  'project-app': {
    name: 'Project Management',
    sessions: new Map(),
  },
  'wiki-app': {
    name: 'Internal Wiki',
    sessions: new Map(),
  },
};

// ---------------------------------------------------------------------------
// SAML-like Assertion Functions
// ---------------------------------------------------------------------------

/**
 * Creates a signed SAML-like assertion (using JWT for simplicity).
 *
 * In real SAML, this would be an XML document with:
 * - Issuer: The IdP identifier
 * - Subject: The authenticated user
 * - Conditions: Validity period, audience restrictions
 * - AuthnStatement: How the user authenticated
 * - AttributeStatement: User attributes (email, groups, etc.)
 *
 * The assertion is signed with the IdP's private key (simulated here
 * with HMAC). SPs verify the signature using the IdP's public key.
 */
function createSAMLAssertion(user, targetService) {
  const assertion = {
    // Issuer -- identifies the IdP
    issuer: 'sso-demo-idp',

    // Subject -- the authenticated user
    subject: {
      nameId: user.email, // SAML NameID (usually email or employee ID)
      nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
    },

    // User attributes
    attributes: {
      userId: user.id,
      username: user.username,
      email: user.email,
      displayName: user.displayName,
      department: user.department,
      groups: user.groups,
    },

    // Conditions
    audience: targetService, // Which SP this assertion is intended for
    notBefore: new Date().toISOString(),

    // Authentication context
    authnContext: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',

    // Unique assertion ID
    assertionId: uuidv4(),
  };

  // Sign the assertion (simulates XML digital signature)
  const signedAssertion = jwt.sign(assertion, IDP_SIGNING_SECRET, {
    expiresIn: ASSERTION_EXPIRY,
    algorithm: 'HS256',
  });

  console.log(`[IdP] Created SAML assertion for "${user.username}" targeting "${targetService}"`);

  return signedAssertion;
}

/**
 * Verifies a SAML-like assertion.
 * In real SAML, this would validate the XML signature using the IdP's
 * public certificate.
 */
function verifySAMLAssertion(assertion, expectedAudience) {
  try {
    const decoded = jwt.verify(assertion, IDP_SIGNING_SECRET, {
      algorithms: ['HS256'],
    });

    // Verify audience restriction
    if (decoded.audience !== expectedAudience) {
      console.log(`[SP] Audience mismatch: expected "${expectedAudience}", got "${decoded.audience}"`);
      return { valid: false, error: 'Audience mismatch' };
    }

    console.log(`[SP] Valid assertion for "${decoded.attributes.username}" (audience: ${decoded.audience})`);
    return { valid: true, claims: decoded };
  } catch (err) {
    console.log(`[SP] Invalid assertion: ${err.message}`);
    return { valid: false, error: err.message };
  }
}

// ---------------------------------------------------------------------------
// Routes -- Public Info
// ---------------------------------------------------------------------------

app.get('/', (req, res) => {
  res.json({
    message: 'Welcome to the SSO Simulation demo server',
    description: 'This server simulates an Identity Provider (IdP) and multiple Service Providers (SPs)',
    endpoints: {
      'POST /sso/login': 'Authenticate with the IdP (start SSO flow)',
      'POST /sso/callback/:service': 'SP receives SAML assertion (callback)',
      'GET /sso/initiate/:service': 'SP-initiated SSO (redirects to IdP)',
      'GET /services/:service/data': 'Access service data (requires SP session)',
      'GET /sso/status': 'View SSO session status across all services',
      'POST /sso/logout': 'Single Logout (SLO) -- logout from all services',
    },
    services: Object.keys(services).map((key) => ({
      id: key,
      name: services[key].name,
    })),
    ssoFlows: {
      saml: [
        '1. User visits Service Provider (SP)',
        '2. SP redirects to Identity Provider (IdP) with AuthnRequest',
        '3. User authenticates at IdP',
        '4. IdP POSTs signed SAML assertion to SP Assertion Consumer Service',
        '5. SP validates assertion signature',
        '6. SP creates local session',
      ],
      oidc: [
        '1. User visits Service Provider (SP)',
        '2. SP redirects to IdP authorization endpoint',
        '3. User authenticates at IdP',
        '4. IdP redirects back with authorization code',
        '5. SP exchanges code for ID token + access token',
        '6. SP reads user claims from ID token (JWT)',
      ],
    },
  });
});

// ---------------------------------------------------------------------------
// Identity Provider Routes
// ---------------------------------------------------------------------------

/**
 * IdP Login endpoint.
 * Simulates the Identity Provider's login page.
 *
 * In a real SAML flow:
 * - The user would be redirected to the IdP's login page.
 * - After login, the IdP would redirect back with a SAML assertion.
 *
 * Here we combine it into a single API call for simplicity.
 *
 * Body: { "username": "...", "password": "...", "targetService": "email-app" }
 */
app.post('/sso/login', async (req, res) => {
  console.log('\n[IdP] === SSO LOGIN ===');

  const { username, password, targetService } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      error: 'Bad request',
      message: 'Username and password are required',
    });
  }

  // Validate target service
  if (targetService && !services[targetService]) {
    return res.status(400).json({
      error: 'Invalid service',
      message: `Unknown service: ${targetService}. Available: ${Object.keys(services).join(', ')}`,
    });
  }

  // Authenticate user at the IdP
  const user = idpUsers.find((u) => u.username === username);

  if (!user) {
    console.log(`[IdP] User "${username}" not found`);
    return res.status(401).json({
      error: 'Authentication failed',
      message: 'Invalid credentials',
    });
  }

  const isPasswordValid = await bcrypt.compare(password, user.passwordHash);

  if (!isPasswordValid) {
    console.log(`[IdP] Invalid password for "${username}"`);
    return res.status(401).json({
      error: 'Authentication failed',
      message: 'Invalid credentials',
    });
  }

  console.log(`[IdP] User "${username}" authenticated successfully`);

  // Create an IdP session
  const idpSessionId = uuidv4();
  idpSessions.set(idpSessionId, {
    userId: user.id,
    username: user.username,
    authenticatedAt: new Date().toISOString(),
    services: [], // Track which SPs have been accessed
  });

  // If a target service was specified, generate a SAML assertion for it
  const assertions = {};
  const serviceTargets = targetService ? [targetService] : Object.keys(services);

  // Generate assertions for target service(s)
  // In real SSO, assertions are generated on-demand as the user visits each SP
  for (const svc of serviceTargets) {
    assertions[svc] = createSAMLAssertion(user, svc);
  }

  console.log(`[IdP] Generated ${Object.keys(assertions).length} assertion(s)`);

  res.json({
    message: 'SSO authentication successful',
    idpSession: idpSessionId,
    user: {
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      email: user.email,
    },
    assertions: assertions,
    instructions: {
      step1: 'You have been authenticated by the IdP',
      step2: 'Use the assertion(s) to create sessions at Service Providers',
      step3: `POST /sso/callback/<service> with { "assertion": "<assertion>" }`,
      example: targetService
        ? `POST /sso/callback/${targetService} with the assertion above`
        : 'POST /sso/callback/email-app with the email-app assertion',
    },
  });
});

/**
 * SP-Initiated SSO.
 * Simulates a user trying to access a service that redirects them to the IdP.
 *
 * In real SAML:
 * - SP generates a SAML AuthnRequest and redirects the user to the IdP.
 * - IdP authenticates the user and sends back a SAML Response.
 *
 * This endpoint shows the SP-initiated flow conceptually.
 */
app.get('/sso/initiate/:service', (req, res) => {
  const { service } = req.params;

  if (!services[service]) {
    return res.status(404).json({
      error: 'Service not found',
      message: `Unknown service: ${service}. Available: ${Object.keys(services).join(', ')}`,
    });
  }

  console.log(`\n[SP:${service}] SP-initiated SSO flow`);
  console.log(`[SP:${service}] In production, this would redirect to the IdP login page`);

  res.json({
    message: `SP-initiated SSO for ${services[service].name}`,
    flow: [
      `1. You want to access "${services[service].name}"`,
      '2. The SP sees you have no session',
      '3. SP redirects you to the IdP with a SAML AuthnRequest',
      '4. You authenticate at the IdP (POST /sso/login)',
      '5. IdP sends SAML assertion back to SP',
      `6. POST /sso/callback/${service} with the assertion`,
      '7. SP validates assertion and creates your local session',
    ],
    action: {
      loginUrl: '/sso/login',
      body: {
        username: '<your-username>',
        password: '<your-password>',
        targetService: service,
      },
    },
  });
});

/**
 * SP Callback (Assertion Consumer Service).
 * This is where the SP receives and validates the SAML assertion from the IdP.
 *
 * In real SAML:
 * - The IdP POSTs the SAML Response (containing the assertion) to this URL.
 * - The SP validates the XML signature using the IdP's public certificate.
 * - The SP extracts user attributes from the assertion.
 * - The SP creates a local session for the user.
 *
 * Body: { "assertion": "<signed-assertion>" }
 */
app.post('/sso/callback/:service', (req, res) => {
  const { service } = req.params;

  if (!services[service]) {
    return res.status(404).json({
      error: 'Service not found',
      message: `Unknown service: ${service}`,
    });
  }

  console.log(`\n[SP:${service}] === ASSERTION CONSUMER SERVICE ===`);

  const { assertion } = req.body;

  if (!assertion) {
    return res.status(400).json({
      error: 'Bad request',
      message: 'SAML assertion is required',
    });
  }

  // Verify the assertion (simulates X.509 signature verification)
  const result = verifySAMLAssertion(assertion, service);

  if (!result.valid) {
    console.log(`[SP:${service}] Assertion validation failed: ${result.error}`);
    return res.status(401).json({
      error: 'Invalid assertion',
      message: `SAML assertion validation failed: ${result.error}`,
    });
  }

  const { claims } = result;
  console.log(`[SP:${service}] Assertion validated for "${claims.attributes.username}"`);

  // Create a local session at this SP
  const sessionToken = uuidv4();
  services[service].sessions.set(sessionToken, {
    userId: claims.attributes.userId,
    username: claims.attributes.username,
    email: claims.attributes.email,
    displayName: claims.attributes.displayName,
    department: claims.attributes.department,
    groups: claims.attributes.groups,
    authenticatedVia: 'SSO',
    idpIssuer: claims.issuer,
    sessionCreatedAt: new Date().toISOString(),
  });

  console.log(`[SP:${service}] Local session created for "${claims.attributes.username}"`);
  console.log(`[SP:${service}] Active sessions: ${services[service].sessions.size}`);

  res.json({
    message: `SSO session created at ${services[service].name}`,
    service: service,
    sessionToken: sessionToken,
    user: claims.attributes,
    info: 'Use this session token to access service resources',
    usage: `GET /services/${service}/data with header: Authorization: Bearer ${sessionToken}`,
  });
});

// ---------------------------------------------------------------------------
// Service Provider -- Protected Resources
// ---------------------------------------------------------------------------

/**
 * Middleware to verify a service-specific session.
 */
function requireServiceSession(service) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Authentication required',
        message: `No session for ${services[service].name}. Complete SSO login first.`,
        ssoLoginUrl: '/sso/login',
      });
    }

    const token = authHeader.split(' ')[1];
    const session = services[service].sessions.get(token);

    if (!session) {
      return res.status(401).json({
        error: 'Invalid session',
        message: 'Your session is invalid or has been terminated.',
      });
    }

    req.serviceUser = session;
    req.serviceToken = token;
    next();
  };
}

/**
 * Access service data (requires an active SP session).
 */
app.get('/services/:service/data', (req, res, next) => {
  const { service } = req.params;

  if (!services[service]) {
    return res.status(404).json({
      error: 'Service not found',
      message: `Unknown service: ${service}`,
    });
  }

  requireServiceSession(service)(req, res, () => {
    console.log(`[SP:${service}] Serving data for "${req.serviceUser.username}"`);

    // Simulated data per service
    const serviceData = {
      'email-app': {
        inbox: [
          { from: 'hr@company.com', subject: 'Team Lunch Friday', read: false },
          { from: 'cto@company.com', subject: 'Q4 Planning', read: true },
        ],
      },
      'project-app': {
        projects: [
          { name: 'Website Redesign', status: 'In Progress', tasks: 12 },
          { name: 'API Migration', status: 'Planning', tasks: 5 },
        ],
      },
      'wiki-app': {
        recentPages: [
          { title: 'Onboarding Guide', lastEdited: '2024-01-15' },
          { title: 'Architecture Overview', lastEdited: '2024-01-10' },
        ],
      },
    };

    res.json({
      service: services[service].name,
      user: {
        username: req.serviceUser.username,
        displayName: req.serviceUser.displayName,
        authenticatedVia: req.serviceUser.authenticatedVia,
      },
      data: serviceData[service] || {},
    });
  });
});

// ---------------------------------------------------------------------------
// SSO Status -- View sessions across all services
// ---------------------------------------------------------------------------

/**
 * Shows the user's SSO session status across all services.
 * This demonstrates the "single sign-on" effect where one authentication
 * grants access to multiple services.
 */
app.get('/sso/status', (req, res) => {
  console.log('\n[SSO] Status check');

  const status = {};

  for (const [serviceId, service] of Object.entries(services)) {
    const sessionCount = service.sessions.size;
    const activeSessions = [];

    for (const [token, data] of service.sessions) {
      activeSessions.push({
        username: data.username,
        displayName: data.displayName,
        authenticatedVia: data.authenticatedVia,
        sessionCreatedAt: data.sessionCreatedAt,
      });
    }

    status[serviceId] = {
      name: service.name,
      activeSessions: sessionCount,
      sessions: activeSessions,
    };
  }

  res.json({
    message: 'SSO Session Status',
    idpActiveSessions: idpSessions.size,
    serviceStatus: status,
  });
});

// ---------------------------------------------------------------------------
// Single Logout (SLO)
// ---------------------------------------------------------------------------

/**
 * Single Logout -- terminates sessions across ALL services.
 *
 * In real SAML SLO:
 * - The IdP sends LogoutRequest to each SP.
 * - Each SP destroys the local session and responds with LogoutResponse.
 * - The IdP destroys its own session.
 *
 * In OIDC:
 * - The client calls the end_session_endpoint.
 * - The IdP may use backchannel logout to notify SPs.
 *
 * Body: { "idpSession": "<session-id>" }
 */
app.post('/sso/logout', (req, res) => {
  console.log('\n[SSO] === SINGLE LOGOUT (SLO) ===');

  const { idpSession, username } = req.body;

  // Find the user to logout
  let targetUsername = username;

  if (idpSession) {
    const session = idpSessions.get(idpSession);
    if (session) {
      targetUsername = session.username;
      idpSessions.delete(idpSession);
      console.log(`[IdP] Destroyed IdP session for "${targetUsername}"`);
    }
  }

  if (!targetUsername) {
    return res.status(400).json({
      error: 'Bad request',
      message: 'Provide idpSession or username to logout',
    });
  }

  // Destroy sessions across all Service Providers (simulates SLO)
  const logoutResults = {};

  for (const [serviceId, service] of Object.entries(services)) {
    let destroyed = 0;

    for (const [token, data] of service.sessions) {
      if (data.username === targetUsername) {
        service.sessions.delete(token);
        destroyed++;
      }
    }

    logoutResults[serviceId] = {
      name: service.name,
      sessionsDestroyed: destroyed,
    };

    if (destroyed > 0) {
      console.log(`[SP:${serviceId}] Destroyed ${destroyed} session(s) for "${targetUsername}"`);
    }
  }

  console.log(`[SSO] SLO complete for "${targetUsername}"`);

  res.json({
    message: `Single Logout completed for "${targetUsername}"`,
    logoutResults,
    info: 'All sessions across all services have been terminated.',
    samlNote: 'In real SAML SLO, the IdP sends LogoutRequest to each SP via backchannel or redirect.',
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
    console.log(`  SSO Simulation Server running on port ${PORT}`);
    console.log(`========================================`);
    console.log(`\nThis server simulates:`);
    console.log(`  - Identity Provider (IdP): Authenticates users`);
    console.log(`  - 3 Service Providers (SPs): email-app, project-app, wiki-app`);
    console.log(`\nTest the full SSO flow:`);
    console.log(`\n  # Step 1: Authenticate with the IdP`);
    console.log(`  curl -X POST http://localhost:${PORT}/sso/login \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"username":"alice","password":"password123","targetService":"email-app"}'`);
    console.log(`\n  # Step 2: Use the assertion to create a session at the SP`);
    console.log(`  curl -X POST http://localhost:${PORT}/sso/callback/email-app \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"assertion":"<ASSERTION_FROM_STEP_1>"}'`);
    console.log(`\n  # Step 3: Access the service with your session token`);
    console.log(`  curl http://localhost:${PORT}/services/email-app/data \\`);
    console.log(`    -H "Authorization: Bearer <SESSION_TOKEN_FROM_STEP_2>"`);
    console.log(`\n  # View SSO status across all services:`);
    console.log(`  curl http://localhost:${PORT}/sso/status`);
    console.log(`\n  # Single Logout (terminates all sessions):`);
    console.log(`  curl -X POST http://localhost:${PORT}/sso/logout \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"username":"alice"}'`);
  });
});
