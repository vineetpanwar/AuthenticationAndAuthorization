/**
 * ============================================================================
 * SAML 2.0 (Security Assertion Markup Language) SSO Simulation
 * ============================================================================
 *
 * What is SAML?
 * -------------
 * SAML 2.0 is an XML-based open standard for exchanging authentication and
 * authorization data between an Identity Provider (IdP) and a Service Provider
 * (SP). It is the dominant SSO protocol in enterprise environments.
 *
 * Key Concepts:
 * - IdP (Identity Provider): Authenticates users (e.g., Okta, Azure AD, ADFS)
 * - SP (Service Provider): The application the user wants to access (e.g., Salesforce, Jira)
 * - Assertion: A signed XML document containing the user's identity and attributes
 * - ACS (Assertion Consumer Service): The SP endpoint that receives SAML assertions
 * - AuthnRequest: The XML request the SP sends to the IdP to initiate login
 * - Binding: How SAML messages are transported (HTTP POST, HTTP Redirect)
 *
 * SAML Flow (SP-Initiated):
 * 1. User visits SP (e.g., Jira)
 * 2. SP generates a SAML AuthnRequest XML
 * 3. SP redirects user to IdP with the AuthnRequest (via HTTP Redirect or POST)
 * 4. User authenticates at IdP (if no existing IdP session)
 * 5. IdP generates a signed SAML Response containing an Assertion
 * 6. IdP POSTs the SAML Response to the SP's ACS URL
 * 7. SP validates the XML signature using the IdP's X.509 certificate
 * 8. SP extracts user attributes from the Assertion
 * 9. SP creates a local session
 *
 * This simulation uses JWTs to simulate XML signatures for simplicity.
 * In production, you'd use a SAML library (passport-saml, saml2-js, etc.)
 *
 * Run: npm run saml
 * ============================================================================
 */

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const app = express();
const PORT = 3013;
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
// In real SAML, the IdP signs assertions with an X.509 certificate (RSA/ECDSA).
// The SP validates using the IdP's public certificate from metadata XML.
const IDP_SIGNING_KEY = 'saml-idp-signing-key-simulates-x509-private-key';
const IDP_ENTITY_ID = 'https://idp.example.com/saml/metadata';
const ASSERTION_VALIDITY_SECONDS = 300; // 5 minutes (SAML assertions are short-lived)

// ---------------------------------------------------------------------------
// IdP User Store
// ---------------------------------------------------------------------------
const idpUsers = [];

async function initializeUsers() {
  idpUsers.push({
    id: 'user-001',
    username: 'alice',
    passwordHash: await bcrypt.hash('password123', 10),
    email: 'alice@company.com',
    displayName: 'Alice Johnson',
    department: 'Engineering',
    groups: ['engineering', 'admin'],
    employeeId: 'EMP-001',
  });
  idpUsers.push({
    id: 'user-002',
    username: 'bob',
    passwordHash: await bcrypt.hash('secret456', 10),
    email: 'bob@company.com',
    displayName: 'Bob Smith',
    department: 'Marketing',
    groups: ['marketing'],
    employeeId: 'EMP-002',
  });
  console.log('[IdP] Users initialized: alice:password123, bob:secret456');
}

// ---------------------------------------------------------------------------
// IdP Session Store & SP Registry
// ---------------------------------------------------------------------------
const idpSessions = new Map();

// Registered Service Providers (in real SAML, these come from SP metadata XML)
const registeredSPs = {
  'sp-jira': {
    name: 'Jira',
    entityId: 'https://jira.company.com/saml/metadata',
    acsUrl: '/saml/acs/sp-jira',
    sessions: new Map(),
  },
  'sp-confluence': {
    name: 'Confluence',
    entityId: 'https://confluence.company.com/saml/metadata',
    acsUrl: '/saml/acs/sp-confluence',
    sessions: new Map(),
  },
  'sp-salesforce': {
    name: 'Salesforce',
    entityId: 'https://salesforce.company.com/saml/metadata',
    acsUrl: '/saml/acs/sp-salesforce',
    sessions: new Map(),
  },
};

// ---------------------------------------------------------------------------
// SAML Assertion Generation (simulated XML with JWT)
// ---------------------------------------------------------------------------
function createSAMLResponse(user, spId, requestId) {
  const sp = registeredSPs[spId];
  const now = new Date();

  // In real SAML, this would be a full XML document:
  // <samlp:Response>
  //   <saml:Assertion>
  //     <saml:Issuer>https://idp.example.com</saml:Issuer>
  //     <ds:Signature>...</ds:Signature>
  //     <saml:Subject>
  //       <saml:NameID Format="email">alice@company.com</saml:NameID>
  //     </saml:Subject>
  //     <saml:Conditions NotBefore="..." NotOnOrAfter="...">
  //       <saml:AudienceRestriction>
  //         <saml:Audience>https://jira.company.com</saml:Audience>
  //       </saml:AudienceRestriction>
  //     </saml:Conditions>
  //     <saml:AuthnStatement AuthnInstant="...">
  //       <saml:AuthnContext>PasswordProtectedTransport</saml:AuthnContext>
  //     </saml:AuthnStatement>
  //     <saml:AttributeStatement>
  //       <saml:Attribute Name="email"><saml:AttributeValue>alice@company.com</saml:AttributeValue></saml:Attribute>
  //     </saml:AttributeStatement>
  //   </saml:Assertion>
  // </samlp:Response>

  const assertion = {
    // SAML Response metadata
    responseId: '_' + uuidv4(),
    inResponseTo: requestId,
    issueInstant: now.toISOString(),
    destination: sp.acsUrl,

    // Issuer (the IdP)
    issuer: IDP_ENTITY_ID,

    // Status
    status: 'urn:oasis:names:tc:SAML:2.0:status:Success',

    // Assertion
    assertionId: '_' + uuidv4(),

    // Subject with NameID
    subject: {
      nameId: user.email,
      nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
      subjectConfirmation: {
        method: 'urn:oasis:names:tc:SAML:2.0:cm:bearer',
        inResponseTo: requestId,
        recipient: sp.acsUrl,
      },
    },

    // Conditions (validity + audience restriction)
    conditions: {
      notBefore: now.toISOString(),
      notOnOrAfter: new Date(now.getTime() + ASSERTION_VALIDITY_SECONDS * 1000).toISOString(),
      audienceRestriction: sp.entityId,
    },

    // Authentication Statement
    authnStatement: {
      authnInstant: now.toISOString(),
      sessionIndex: '_' + uuidv4(),
      authnContext: 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
    },

    // Attribute Statement (user claims)
    attributes: {
      userId: user.id,
      username: user.username,
      email: user.email,
      displayName: user.displayName,
      department: user.department,
      groups: user.groups,
      employeeId: user.employeeId,
    },
  };

  // Sign the assertion (simulates XML digital signature with X.509)
  const signedResponse = jwt.sign(assertion, IDP_SIGNING_KEY, {
    expiresIn: ASSERTION_VALIDITY_SECONDS,
  });

  console.log(`[IdP] Created SAML Response for "${user.username}" -> ${sp.name}`);
  return { signed: signedResponse, raw: assertion };
}

function verifySAMLResponse(signedResponse, expectedSpEntityId) {
  try {
    const decoded = jwt.verify(signedResponse, IDP_SIGNING_KEY);

    // Verify audience restriction
    if (decoded.conditions.audienceRestriction !== expectedSpEntityId) {
      return { valid: false, error: 'Audience restriction mismatch' };
    }

    // Verify issuer
    if (decoded.issuer !== IDP_ENTITY_ID) {
      return { valid: false, error: 'Unknown issuer' };
    }

    return { valid: true, assertion: decoded };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

app.get('/', (req, res) => {
  res.json({
    message: 'SAML 2.0 SSO Simulation',
    protocol: 'SAML 2.0',
    description: 'XML-based SSO protocol used in enterprise environments',
    endpoints: {
      'POST /saml/authn-request/:spId': 'SP-initiated SSO: SP sends AuthnRequest to IdP',
      'POST /saml/idp/login': 'IdP authenticates user and returns SAML Response',
      'POST /saml/acs/:spId': 'SP Assertion Consumer Service: validates assertion, creates session',
      'GET /saml/sp/:spId/data': 'Access SP data (requires SAML session)',
      'POST /saml/slo': 'Single Logout across all SPs',
      'GET /saml/metadata/idp': 'IdP metadata (entity ID, certificates, endpoints)',
      'GET /saml/metadata/sp/:spId': 'SP metadata (entity ID, ACS URL)',
    },
    registeredSPs: Object.entries(registeredSPs).map(([id, sp]) => ({
      id, name: sp.name, entityId: sp.entityId,
    })),
  });
});

// IdP Metadata (what SPs download to configure trust)
app.get('/saml/metadata/idp', (req, res) => {
  res.json({
    entityId: IDP_ENTITY_ID,
    ssoService: {
      binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      location: '/saml/idp/login',
    },
    sloService: {
      binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      location: '/saml/slo',
    },
    nameIdFormats: [
      'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
      'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    ],
    signingCertificate: '(X.509 certificate would be here in production)',
    note: 'In production, this would be XML. SPs import this to establish trust.',
  });
});

// SP Metadata
app.get('/saml/metadata/sp/:spId', (req, res) => {
  const sp = registeredSPs[req.params.spId];
  if (!sp) return res.status(404).json({ error: 'Unknown SP' });
  res.json({
    entityId: sp.entityId,
    assertionConsumerService: {
      binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      location: sp.acsUrl,
    },
    note: 'In production, this would be XML. The IdP imports this to know where to send assertions.',
  });
});

// SP-Initiated SSO: SP generates AuthnRequest
app.post('/saml/authn-request/:spId', (req, res) => {
  const sp = registeredSPs[req.params.spId];
  if (!sp) return res.status(404).json({ error: 'Unknown SP' });

  const requestId = '_' + uuidv4();
  console.log(`\n[SP:${sp.name}] Generated SAML AuthnRequest (ID: ${requestId})`);

  res.json({
    step: '1 of 4 — SP generates AuthnRequest',
    authnRequest: {
      id: requestId,
      issuer: sp.entityId,
      destination: '/saml/idp/login',
      assertionConsumerServiceURL: sp.acsUrl,
      protocolBinding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      nameIdPolicy: 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress',
      issueInstant: new Date().toISOString(),
    },
    nextStep: {
      description: 'Now POST to the IdP login with your credentials and this request context',
      url: '/saml/idp/login',
      body: {
        username: '<username>',
        password: '<password>',
        spId: req.params.spId,
        requestId: requestId,
      },
    },
  });
});

// IdP Login: Authenticate user and generate SAML Response
app.post('/saml/idp/login', async (req, res) => {
  const { username, password, spId, requestId } = req.body;
  console.log(`\n[IdP] === SAML Authentication ===`);

  if (!username || !password || !spId) {
    return res.status(400).json({ error: 'username, password, and spId required' });
  }

  const sp = registeredSPs[spId];
  if (!sp) return res.status(400).json({ error: `Unknown SP: ${spId}` });

  // Authenticate
  const user = idpUsers.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Authentication failed' });
  }

  console.log(`[IdP] User "${username}" authenticated`);

  // Create IdP session
  const sessionId = uuidv4();
  idpSessions.set(sessionId, {
    userId: user.id, username: user.username,
    authenticatedAt: new Date().toISOString(),
    authnMethod: 'password',
  });

  // Generate SAML Response
  const samlResponse = createSAMLResponse(user, spId, requestId || '_' + uuidv4());

  res.json({
    step: '2 of 4 — IdP authenticates user and creates SAML Response',
    message: `SAML Response generated for ${sp.name}`,
    idpSession: sessionId,
    samlResponse: samlResponse.signed,
    decodedAssertion: {
      issuer: samlResponse.raw.issuer,
      subject: samlResponse.raw.subject,
      conditions: samlResponse.raw.conditions,
      authnStatement: samlResponse.raw.authnStatement,
      attributeCount: Object.keys(samlResponse.raw.attributes).length,
    },
    nextStep: {
      description: 'POST the SAML Response to the SP Assertion Consumer Service',
      url: sp.acsUrl,
      body: { SAMLResponse: samlResponse.signed },
    },
  });
});

// SP Assertion Consumer Service: Receive and validate SAML Response
app.post('/saml/acs/:spId', (req, res) => {
  const spId = req.params.spId;
  const sp = registeredSPs[spId];
  if (!sp) return res.status(404).json({ error: 'Unknown SP' });

  console.log(`\n[SP:${sp.name}] === Assertion Consumer Service ===`);

  const { SAMLResponse } = req.body;
  if (!SAMLResponse) {
    return res.status(400).json({ error: 'SAMLResponse required' });
  }

  // Validate SAML Response (simulates XML signature verification)
  const result = verifySAMLResponse(SAMLResponse, sp.entityId);
  if (!result.valid) {
    console.log(`[SP:${sp.name}] Assertion validation FAILED: ${result.error}`);
    return res.status(401).json({ error: 'SAML assertion invalid', detail: result.error });
  }

  const { assertion } = result;
  console.log(`[SP:${sp.name}] Valid assertion for "${assertion.attributes.username}"`);

  // Create SP session
  const sessionToken = uuidv4();
  sp.sessions.set(sessionToken, {
    ...assertion.attributes,
    authenticatedVia: 'SAML 2.0',
    sessionIndex: assertion.authnStatement.sessionIndex,
    idpIssuer: assertion.issuer,
    createdAt: new Date().toISOString(),
  });

  res.json({
    step: '3 of 4 — SP validates assertion and creates session',
    message: `SAML SSO session created at ${sp.name}`,
    sessionToken,
    user: assertion.attributes,
    usage: `GET /saml/sp/${spId}/data -H "Authorization: Bearer ${sessionToken}"`,
  });
});

// SP Protected Data
app.get('/saml/sp/:spId/data', (req, res) => {
  const sp = registeredSPs[req.params.spId];
  if (!sp) return res.status(404).json({ error: 'Unknown SP' });

  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const session = sp.sessions.get(token);
  if (!session) {
    return res.status(401).json({ error: 'No valid session. Complete SAML SSO first.' });
  }

  res.json({
    step: '4 of 4 — Access SP resources with SAML session',
    service: sp.name,
    user: { username: session.username, email: session.email, authenticatedVia: session.authenticatedVia },
    data: { message: `Welcome to ${sp.name}! You were authenticated via SAML 2.0 SSO.` },
  });
});

// Single Logout
app.post('/saml/slo', (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'username required' });

  console.log(`\n[SLO] Logging out "${username}" from all SPs`);
  const results = {};
  for (const [spId, sp] of Object.entries(registeredSPs)) {
    let count = 0;
    for (const [tok, sess] of sp.sessions) {
      if (sess.username === username) { sp.sessions.delete(tok); count++; }
    }
    results[spId] = { name: sp.name, sessionsDestroyed: count };
  }

  // Also clear IdP sessions
  for (const [sid, sess] of idpSessions) {
    if (sess.username === username) idpSessions.delete(sid);
  }

  res.json({ message: `SAML SLO complete for "${username}"`, results });
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
    console.log(`  SAML 2.0 SSO Server running on port ${PORT}`);
    console.log(`========================================`);
    console.log(`\nTest the full SAML SP-initiated flow:`);
    console.log(`\n  # Step 1: SP generates AuthnRequest`);
    console.log(`  curl -X POST http://localhost:${PORT}/saml/authn-request/sp-jira`);
    console.log(`\n  # Step 2: Authenticate at IdP`);
    console.log(`  curl -X POST http://localhost:${PORT}/saml/idp/login \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"username":"alice","password":"password123","spId":"sp-jira"}'`);
    console.log(`\n  # Step 3: Post SAML Response to SP ACS`);
    console.log(`  curl -X POST http://localhost:${PORT}/saml/acs/sp-jira \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"SAMLResponse":"<TOKEN_FROM_STEP_2>"}'`);
    console.log(`\n  # Step 4: Access SP data`);
    console.log(`  curl http://localhost:${PORT}/saml/sp/sp-jira/data \\`);
    console.log(`    -H "Authorization: Bearer <SESSION_FROM_STEP_3>"`);
  });
});
