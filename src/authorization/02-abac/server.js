/**
 * ============================================================================
 * ATTRIBUTE-BASED ACCESS CONTROL (ABAC) - Authorization Server
 * ============================================================================
 *
 * WHAT IS ABAC?
 * Attribute-Based Access Control makes access decisions based on attributes
 * (properties) of the subject (user), the resource, the action, and the
 * environment/context. Instead of fixed roles, ABAC evaluates dynamic
 * policies against these attributes at the time of the request.
 *
 * HOW IT WORKS:
 *   (Subject Attributes + Resource Attributes + Action + Environment Attributes)
 *       --> Policy Engine --> Allow / Deny
 *
 * KEY CONCEPTS:
 *   - Subject Attributes: Properties of the user (department, clearance, title, etc.)
 *   - Resource Attributes: Properties of the resource (classification, owner, type, etc.)
 *   - Action: The operation being performed (read, write, delete, approve, etc.)
 *   - Environment Attributes: Contextual factors (time of day, IP address, device, etc.)
 *   - Policy: A rule that combines attributes to make an access decision
 *   - Policy Engine: The component that evaluates policies against current attributes
 *
 * REAL-WORLD EXAMPLES:
 *   - Healthcare (HIPAA): "Only doctors in the same department as the patient
 *     can view patient records during their shift hours"
 *   - Finance: "Traders can only execute trades under $1M; above $1M requires
 *     a senior trader with compliance certification"
 *   - Government: "Only users with SECRET clearance in the Defense department
 *     can access SECRET-classified documents"
 *   - HR Systems: "HR staff can view employee records in their own region,
 *     but only during business hours and from the office network"
 *   - AWS IAM Conditions: IP range conditions, time-based conditions, MFA requirements
 *
 * PROS:
 *   - Extremely flexible and fine-grained
 *   - Context-aware (time, location, device, etc.)
 *   - Scales to complex authorization requirements
 *   - Policies can be changed without modifying code
 *   - No "role explosion" problem
 *
 * CONS:
 *   - More complex to implement and understand
 *   - Harder to audit ("why was this allowed/denied?")
 *   - Performance cost of evaluating complex policies
 *   - Requires well-defined attribute schemas
 *   - Can be difficult to debug
 *
 * THIS DEMO:
 *   Simulates a corporate document management system where access depends
 *   on user department, clearance level, document classification, time of day,
 *   and network location.
 *
 * Port: 3009
 * ============================================================================
 */

const express = require('express');
const app = express();
const PORT = 3009;

app.use(express.json());

// =============================================================================
// SECTION 1: Attribute Definitions
// =============================================================================

/**
 * Define the valid values for each attribute category.
 * In production, these might come from an identity provider (IdP),
 * HR system, or configuration database.
 */

// Department hierarchy
const DEPARTMENTS = ['engineering', 'hr', 'finance', 'legal', 'marketing', 'executive'];

// Clearance levels (ordered from lowest to highest)
const CLEARANCE_LEVELS = {
  public: 0,
  internal: 1,
  confidential: 2,
  secret: 3,
  top_secret: 4,
};

// Document classifications (maps to clearance levels)
const CLASSIFICATIONS = {
  public: 0,
  internal: 1,
  confidential: 2,
  secret: 3,
  top_secret: 4,
};

// Business hours definition (used for time-based policies)
const BUSINESS_HOURS = {
  start: 8,  // 8:00 AM
  end: 18,   // 6:00 PM
  // Monday=1, Friday=5
  workDays: [1, 2, 3, 4, 5],
};

// Trusted IP ranges (CIDR notation is common in production; we use simple prefixes here)
const TRUSTED_NETWORKS = {
  office: ['192.168.1.', '10.0.0.'],
  vpn: ['172.16.0.'],
};

// =============================================================================
// SECTION 2: Seed Data - Users (Subjects)
// =============================================================================

/**
 * Each user has various attributes that policies evaluate against.
 * In production, these attributes come from IdP, HR systems, etc.
 */
const users = {
  user1: {
    id: 'user1',
    name: 'Alice Chen',
    email: 'alice@company.com',
    department: 'engineering',
    title: 'Senior Engineer',
    clearanceLevel: 'confidential',
    certifications: ['security_awareness', 'data_handling'],
    region: 'us-west',
    isActive: true,
    managerId: null,  // She's a department head
  },
  user2: {
    id: 'user2',
    name: 'Bob Martinez',
    email: 'bob@company.com',
    department: 'hr',
    title: 'HR Director',
    clearanceLevel: 'secret',
    certifications: ['security_awareness', 'data_handling', 'pii_handling'],
    region: 'us-west',
    isActive: true,
    managerId: null,
  },
  user3: {
    id: 'user3',
    name: 'Carol Williams',
    email: 'carol@company.com',
    department: 'finance',
    title: 'Financial Analyst',
    clearanceLevel: 'confidential',
    certifications: ['security_awareness', 'financial_reporting'],
    region: 'us-east',
    isActive: true,
    managerId: 'user7',
  },
  user4: {
    id: 'user4',
    name: 'David Kim',
    email: 'david@company.com',
    department: 'engineering',
    title: 'Junior Developer',
    clearanceLevel: 'internal',
    certifications: ['security_awareness'],
    region: 'us-west',
    isActive: true,
    managerId: 'user1',
  },
  user5: {
    id: 'user5',
    name: 'Eve Johnson',
    email: 'eve@company.com',
    department: 'executive',
    title: 'CEO',
    clearanceLevel: 'top_secret',
    certifications: ['security_awareness', 'data_handling', 'pii_handling', 'executive_clearance'],
    region: 'us-west',
    isActive: true,
    managerId: null,
  },
  user6: {
    id: 'user6',
    name: 'Frank Brown',
    email: 'frank@company.com',
    department: 'marketing',
    title: 'Marketing Coordinator',
    clearanceLevel: 'public',
    certifications: [],
    region: 'eu-west',
    isActive: true,
    managerId: null,
  },
  user7: {
    id: 'user7',
    name: 'Grace Lee',
    email: 'grace@company.com',
    department: 'finance',
    title: 'CFO',
    clearanceLevel: 'top_secret',
    certifications: ['security_awareness', 'data_handling', 'financial_reporting', 'executive_clearance'],
    region: 'us-east',
    isActive: true,
    managerId: 'user5',
  },
};

// =============================================================================
// SECTION 3: Seed Data - Resources (Documents)
// =============================================================================

/**
 * Each document/resource has its own attributes that policies evaluate.
 * These attributes determine WHO can access the resource and UNDER WHAT CONDITIONS.
 */
const documents = {
  doc1: {
    id: 'doc1',
    title: 'Company Holiday Schedule 2025',
    department: 'hr',
    classification: 'public',
    owner: 'user2',
    type: 'announcement',
    tags: ['company-wide'],
    createdAt: '2025-01-01T00:00:00Z',
  },
  doc2: {
    id: 'doc2',
    title: 'Engineering Architecture Review',
    department: 'engineering',
    classification: 'internal',
    owner: 'user1',
    type: 'technical',
    tags: ['architecture', 'review'],
    createdAt: '2025-01-10T00:00:00Z',
  },
  doc3: {
    id: 'doc3',
    title: 'Employee Salary Database',
    department: 'hr',
    classification: 'confidential',
    owner: 'user2',
    type: 'database',
    tags: ['pii', 'compensation'],
    createdAt: '2025-01-05T00:00:00Z',
  },
  doc4: {
    id: 'doc4',
    title: 'Q4 Financial Report (Draft)',
    department: 'finance',
    classification: 'confidential',
    owner: 'user3',
    type: 'report',
    tags: ['quarterly', 'financial'],
    createdAt: '2025-01-12T00:00:00Z',
  },
  doc5: {
    id: 'doc5',
    title: 'Merger & Acquisition Plan - Project Phoenix',
    department: 'executive',
    classification: 'top_secret',
    owner: 'user5',
    type: 'strategic',
    tags: ['m&a', 'confidential', 'board'],
    createdAt: '2025-01-15T00:00:00Z',
  },
  doc6: {
    id: 'doc6',
    title: 'Security Incident Response Playbook',
    department: 'engineering',
    classification: 'secret',
    owner: 'user1',
    type: 'procedure',
    tags: ['security', 'incident-response'],
    createdAt: '2025-01-08T00:00:00Z',
  },
  doc7: {
    id: 'doc7',
    title: 'Marketing Campaign Brief - Spring 2025',
    department: 'marketing',
    classification: 'internal',
    owner: 'user6',
    type: 'brief',
    tags: ['campaign', 'spring'],
    createdAt: '2025-01-11T00:00:00Z',
  },
};

// Session storage
const sessions = {};

// =============================================================================
// SECTION 4: Policy Engine
// =============================================================================

/**
 * The Policy Engine is the heart of ABAC. It evaluates a set of policies
 * against the current request context (subject, resource, action, environment).
 *
 * Each policy is an object with:
 *   - name: Human-readable name for debugging/auditing
 *   - description: Explanation of the policy
 *   - effect: 'allow' or 'deny'
 *   - condition: A function that receives the context and returns true/false
 *   - priority: Higher priority policies are evaluated first (deny usually wins)
 */

/**
 * Helper: Get the current environment attributes.
 * In production, these would come from the actual request context.
 */
function getEnvironmentAttributes(req) {
  const now = new Date();
  // Allow overriding time/IP for testing via headers
  const simulatedHour = req.headers['x-simulated-hour'];
  const simulatedDay = req.headers['x-simulated-day'];
  const simulatedIp = req.headers['x-simulated-ip'];

  const hour = simulatedHour !== undefined ? parseInt(simulatedHour) : now.getHours();
  const dayOfWeek = simulatedDay !== undefined ? parseInt(simulatedDay) : now.getDay();
  const clientIp = simulatedIp || req.ip || '192.168.1.100';

  const isBusinessHours = hour >= BUSINESS_HOURS.start &&
    hour < BUSINESS_HOURS.end &&
    BUSINESS_HOURS.workDays.includes(dayOfWeek);

  const isOfficeNetwork = TRUSTED_NETWORKS.office.some(prefix => clientIp.startsWith(prefix));
  const isVpnNetwork = TRUSTED_NETWORKS.vpn.some(prefix => clientIp.startsWith(prefix));
  const isTrustedNetwork = isOfficeNetwork || isVpnNetwork;

  return {
    currentTime: now.toISOString(),
    hour,
    dayOfWeek,
    isBusinessHours,
    clientIp,
    isOfficeNetwork,
    isVpnNetwork,
    isTrustedNetwork,
  };
}

/**
 * POLICIES: The rules that govern access.
 *
 * Policies are evaluated in priority order. We use a "deny overrides" strategy:
 * if ANY deny policy matches, access is denied regardless of allow policies.
 * If no deny matches and at least one allow matches, access is granted.
 */
const policies = [
  // -------------------------------------------------------------------------
  // DENY POLICIES (evaluated first due to higher priority)
  // -------------------------------------------------------------------------
  {
    name: 'deny-inactive-users',
    description: 'Inactive users cannot access any resource',
    effect: 'deny',
    priority: 100,
    condition: (ctx) => !ctx.subject.isActive,
  },
  {
    name: 'deny-insufficient-clearance',
    description: 'Users cannot access documents above their clearance level',
    effect: 'deny',
    priority: 90,
    condition: (ctx) => {
      const userClearance = CLEARANCE_LEVELS[ctx.subject.clearanceLevel] || 0;
      const docClassification = CLASSIFICATIONS[ctx.resource.classification] || 0;
      return userClearance < docClassification;
    },
  },
  {
    name: 'deny-pii-without-certification',
    description: 'Documents tagged with PII require pii_handling certification',
    effect: 'deny',
    priority: 85,
    condition: (ctx) => {
      const hasPiiTag = ctx.resource.tags && ctx.resource.tags.includes('pii');
      const hasCert = ctx.subject.certifications &&
        ctx.subject.certifications.includes('pii_handling');
      return hasPiiTag && !hasCert;
    },
  },
  {
    name: 'deny-confidential-outside-business-hours',
    description: 'Confidential and above documents can only be accessed during business hours',
    effect: 'deny',
    priority: 80,
    condition: (ctx) => {
      const classification = CLASSIFICATIONS[ctx.resource.classification] || 0;
      // Confidential (2) and above
      return classification >= 2 && !ctx.environment.isBusinessHours;
    },
  },
  {
    name: 'deny-secret-outside-trusted-network',
    description: 'Secret and top-secret documents require a trusted network (office or VPN)',
    effect: 'deny',
    priority: 75,
    condition: (ctx) => {
      const classification = CLASSIFICATIONS[ctx.resource.classification] || 0;
      // Secret (3) and above
      return classification >= 3 && !ctx.environment.isTrustedNetwork;
    },
  },
  {
    name: 'deny-write-without-data-handling-cert',
    description: 'Writing to confidential+ documents requires data_handling certification',
    effect: 'deny',
    priority: 70,
    condition: (ctx) => {
      const classification = CLASSIFICATIONS[ctx.resource.classification] || 0;
      const isWriteAction = ['write', 'update', 'delete'].includes(ctx.action);
      const hasCert = ctx.subject.certifications &&
        ctx.subject.certifications.includes('data_handling');
      return isWriteAction && classification >= 2 && !hasCert;
    },
  },

  // -------------------------------------------------------------------------
  // ALLOW POLICIES
  // -------------------------------------------------------------------------
  {
    name: 'allow-public-documents',
    description: 'Anyone can read public documents',
    effect: 'allow',
    priority: 50,
    condition: (ctx) => {
      return ctx.resource.classification === 'public' && ctx.action === 'read';
    },
  },
  {
    name: 'allow-owner-full-access',
    description: 'Document owners have full access to their own documents',
    effect: 'allow',
    priority: 55,
    condition: (ctx) => {
      return ctx.resource.owner === ctx.subject.id;
    },
  },
  {
    name: 'allow-same-department-read',
    description: 'Users can read documents from their own department',
    effect: 'allow',
    priority: 45,
    condition: (ctx) => {
      return ctx.subject.department === ctx.resource.department && ctx.action === 'read';
    },
  },
  {
    name: 'allow-same-department-write',
    description: 'Users can write to documents in their own department (if clearance matches)',
    effect: 'allow',
    priority: 44,
    condition: (ctx) => {
      return ctx.subject.department === ctx.resource.department &&
        ['write', 'update'].includes(ctx.action);
    },
  },
  {
    name: 'allow-executive-read-all',
    description: 'Executives can read any document in the company',
    effect: 'allow',
    priority: 50,
    condition: (ctx) => {
      return ctx.subject.department === 'executive' && ctx.action === 'read';
    },
  },
  {
    name: 'allow-hr-read-employee-data',
    description: 'HR department can read employee-related data across departments',
    effect: 'allow',
    priority: 48,
    condition: (ctx) => {
      return ctx.subject.department === 'hr' &&
        ctx.action === 'read' &&
        (ctx.resource.tags || []).some(tag => ['pii', 'compensation', 'employee'].includes(tag));
    },
  },
  {
    name: 'allow-manager-read-subordinate-docs',
    description: 'Managers can read documents owned by their direct reports',
    effect: 'allow',
    priority: 46,
    condition: (ctx) => {
      // Check if the resource owner's manager is the current user
      const resourceOwner = users[ctx.resource.owner];
      return resourceOwner &&
        resourceOwner.managerId === ctx.subject.id &&
        ctx.action === 'read';
    },
  },
  {
    name: 'allow-internal-docs-on-trusted-network',
    description: 'Internal documents can be read by any employee on a trusted network',
    effect: 'allow',
    priority: 40,
    condition: (ctx) => {
      return ctx.resource.classification === 'internal' &&
        ctx.action === 'read' &&
        ctx.environment.isTrustedNetwork;
    },
  },
];

/**
 * The core policy evaluation function.
 *
 * Strategy: "Deny Overrides"
 * 1. Sort policies by priority (highest first)
 * 2. Evaluate deny policies first - if any deny matches, DENY
 * 3. Then evaluate allow policies - if any allow matches, ALLOW
 * 4. Default: DENY (implicit deny - if no policy explicitly allows, deny)
 *
 * Returns: { allowed: boolean, reason: string, matchedPolicies: [] }
 */
function evaluateAccess(subject, resource, action, environment) {
  const context = { subject, resource, action, environment };

  // Sort by priority descending
  const sortedPolicies = [...policies].sort((a, b) => b.priority - a.priority);

  const matchedDeny = [];
  const matchedAllow = [];

  for (const policy of sortedPolicies) {
    try {
      const matches = policy.condition(context);

      if (matches) {
        const record = {
          name: policy.name,
          description: policy.description,
          effect: policy.effect,
          priority: policy.priority,
        };

        if (policy.effect === 'deny') {
          matchedDeny.push(record);
        } else if (policy.effect === 'allow') {
          matchedAllow.push(record);
        }
      }
    } catch (err) {
      console.error(`[POLICY ERROR] Error evaluating policy "${policy.name}":`, err.message);
    }
  }

  // Deny overrides: if any deny matched, access is denied
  if (matchedDeny.length > 0) {
    const primaryDeny = matchedDeny[0]; // Highest priority deny
    console.log(
      `[ABAC] DENIED: "${subject.name}" ${action} "${resource.title}" ` +
      `- matched deny policy: "${primaryDeny.name}"`
    );
    return {
      allowed: false,
      reason: `Denied by policy: ${primaryDeny.description}`,
      matchedPolicies: { deny: matchedDeny, allow: matchedAllow },
    };
  }

  // If at least one allow matched, grant access
  if (matchedAllow.length > 0) {
    const primaryAllow = matchedAllow[0];
    console.log(
      `[ABAC] ALLOWED: "${subject.name}" ${action} "${resource.title}" ` +
      `- matched allow policy: "${primaryAllow.name}"`
    );
    return {
      allowed: true,
      reason: `Allowed by policy: ${primaryAllow.description}`,
      matchedPolicies: { deny: matchedDeny, allow: matchedAllow },
    };
  }

  // Default deny: no policy explicitly allowed this access
  console.log(
    `[ABAC] DENIED (default): "${subject.name}" ${action} "${resource.title}" ` +
    `- no allow policy matched`
  );
  return {
    allowed: false,
    reason: 'Default deny: no policy explicitly grants this access.',
    matchedPolicies: { deny: matchedDeny, allow: matchedAllow },
  };
}

// =============================================================================
// SECTION 5: Middleware
// =============================================================================

/**
 * Middleware: Authenticate the user
 */
function authenticate(req, res, next) {
  const token = req.headers['authorization'];

  if (!token) {
    console.log('[AUTH] No token provided');
    return res.status(401).json({
      error: 'Authentication required',
      message: 'Please log in first. Send POST /login with { "userId": "user1" }',
    });
  }

  const session = sessions[token];
  if (!session) {
    console.log(`[AUTH] Invalid token: ${token}`);
    return res.status(401).json({
      error: 'Invalid or expired token',
    });
  }

  req.user = session.user;
  console.log(`[AUTH] Authenticated: ${req.user.name} (${req.user.department}, clearance: ${req.user.clearanceLevel})`);
  next();
}

/**
 * Middleware Factory: abacCheck
 * Evaluates ABAC policies for a given action against a resource.
 *
 * The resource is determined by the route parameter :docId.
 * The action is specified when creating the middleware.
 *
 * Usage: app.get('/docs/:docId', authenticate, abacCheck('read'), handler)
 */
function abacCheck(action) {
  return (req, res, next) => {
    const docId = req.params.docId;

    if (!docId) {
      return res.status(400).json({ error: 'No document ID provided' });
    }

    const resource = documents[docId];
    if (!resource) {
      return res.status(404).json({
        error: 'Document not found',
        availableDocuments: Object.keys(documents),
      });
    }

    // Gather environment attributes
    const environment = getEnvironmentAttributes(req);

    // Evaluate the policy engine
    const decision = evaluateAccess(req.user, resource, action, environment);

    // Attach decision details to the request for use in the handler
    req.abacDecision = decision;
    req.abacResource = resource;
    req.abacEnvironment = environment;

    if (!decision.allowed) {
      return res.status(403).json({
        error: 'Access denied by ABAC policy',
        action,
        document: { id: resource.id, title: resource.title, classification: resource.classification },
        reason: decision.reason,
        matchedPolicies: decision.matchedPolicies,
        environment: {
          isBusinessHours: environment.isBusinessHours,
          isTrustedNetwork: environment.isTrustedNetwork,
          hour: environment.hour,
          clientIp: environment.clientIp,
        },
        subject: {
          name: req.user.name,
          department: req.user.department,
          clearanceLevel: req.user.clearanceLevel,
          certifications: req.user.certifications,
        },
        hint: 'Use X-Simulated-Hour, X-Simulated-Day, and X-Simulated-IP headers to test different scenarios.',
      });
    }

    next();
  };
}

// =============================================================================
// SECTION 6: Routes
// =============================================================================

// ---------------------
// Public Routes
// ---------------------

/**
 * GET / - API documentation and overview
 */
app.get('/', (req, res) => {
  res.json({
    title: 'ABAC (Attribute-Based Access Control) Demo Server',
    port: PORT,
    description: 'Corporate document management system with fine-grained attribute-based policies',
    policyEngine: {
      strategy: 'Deny Overrides',
      totalPolicies: policies.length,
      denyPolicies: policies.filter(p => p.effect === 'deny').length,
      allowPolicies: policies.filter(p => p.effect === 'allow').length,
    },
    endpoints: {
      public: {
        'POST /login': 'Log in with { "userId": "user1" }',
        'GET /policies': 'View all ABAC policies',
        'GET /documents': 'List all documents (metadata only)',
      },
      protected: {
        'GET /documents/:docId': 'Read a document (evaluates ABAC policies)',
        'PUT /documents/:docId': 'Update a document (evaluates ABAC policies)',
        'DELETE /documents/:docId': 'Delete a document (evaluates ABAC policies)',
        'POST /evaluate': 'Manually test policy evaluation with custom attributes',
        'GET /me': 'View your attributes',
        'GET /me/access-matrix': 'See which documents you can/cannot access and why',
      },
    },
    simulationHeaders: {
      'X-Simulated-Hour': 'Override current hour (0-23) for testing time-based policies',
      'X-Simulated-Day': 'Override day of week (0=Sun, 1=Mon, ..., 6=Sat)',
      'X-Simulated-IP': 'Override client IP for testing network-based policies',
    },
    testUsers: Object.values(users).map(u => ({
      userId: u.id,
      name: u.name,
      department: u.department,
      clearanceLevel: u.clearanceLevel,
      certifications: u.certifications,
    })),
  });
});

/**
 * POST /login - Authenticate a user
 */
app.post('/login', (req, res) => {
  const { userId } = req.body;

  if (!userId || !users[userId]) {
    return res.status(400).json({
      error: 'Invalid userId',
      availableUsers: Object.keys(users).map(id => ({
        userId: id,
        name: users[id].name,
        department: users[id].department,
        clearanceLevel: users[id].clearanceLevel,
      })),
    });
  }

  const user = users[userId];
  const token = `abac-token-${userId}-${Date.now()}`;

  sessions[token] = { user, createdAt: new Date().toISOString() };

  console.log(`[LOGIN] ${user.name} logged in (dept: ${user.department}, clearance: ${user.clearanceLevel})`);

  res.json({
    message: `Welcome, ${user.name}!`,
    token,
    attributes: {
      department: user.department,
      title: user.title,
      clearanceLevel: user.clearanceLevel,
      certifications: user.certifications,
      region: user.region,
    },
    usage: 'Include this token in the Authorization header.',
    tip: 'Use X-Simulated-Hour, X-Simulated-Day, X-Simulated-IP headers to test different scenarios.',
  });
});

/**
 * GET /policies - View all defined ABAC policies
 */
app.get('/policies', (req, res) => {
  res.json({
    strategy: 'Deny Overrides: if any deny policy matches, access is denied regardless of allow policies.',
    policies: policies.map(p => ({
      name: p.name,
      description: p.description,
      effect: p.effect,
      priority: p.priority,
    })).sort((a, b) => b.priority - a.priority),
  });
});

/**
 * GET /documents - List all documents (metadata only, no policy check)
 */
app.get('/documents', (req, res) => {
  res.json({
    documents: Object.values(documents).map(doc => ({
      id: doc.id,
      title: doc.title,
      department: doc.department,
      classification: doc.classification,
      owner: users[doc.owner] ? users[doc.owner].name : doc.owner,
      type: doc.type,
      tags: doc.tags,
    })),
  });
});

// ---------------------
// Protected Routes
// ---------------------

/**
 * GET /me - View your own attributes
 */
app.get('/me', authenticate, (req, res) => {
  res.json({
    attributes: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      department: req.user.department,
      title: req.user.title,
      clearanceLevel: req.user.clearanceLevel,
      clearanceNumeric: CLEARANCE_LEVELS[req.user.clearanceLevel],
      certifications: req.user.certifications,
      region: req.user.region,
      isActive: req.user.isActive,
    },
  });
});

/**
 * GET /me/access-matrix - Shows which documents you can/cannot access
 * This is a powerful audit tool for ABAC systems.
 */
app.get('/me/access-matrix', authenticate, (req, res) => {
  const environment = getEnvironmentAttributes(req);
  const matrix = [];

  for (const doc of Object.values(documents)) {
    const actions = ['read', 'write', 'delete'];
    const access = {};

    for (const action of actions) {
      const decision = evaluateAccess(req.user, doc, action, environment);
      access[action] = {
        allowed: decision.allowed,
        reason: decision.reason,
      };
    }

    matrix.push({
      document: { id: doc.id, title: doc.title, classification: doc.classification, department: doc.department },
      access,
    });
  }

  res.json({
    user: { name: req.user.name, department: req.user.department, clearanceLevel: req.user.clearanceLevel },
    environment: {
      isBusinessHours: environment.isBusinessHours,
      isTrustedNetwork: environment.isTrustedNetwork,
      hour: environment.hour,
      dayOfWeek: environment.dayOfWeek,
      clientIp: environment.clientIp,
    },
    accessMatrix: matrix,
  });
});

/**
 * GET /documents/:docId - Read a document
 * ABAC policy evaluation: action = 'read'
 */
app.get('/documents/:docId', authenticate, abacCheck('read'), (req, res) => {
  const doc = req.abacResource;
  res.json({
    message: `Access granted! You are reading "${doc.title}".`,
    document: {
      id: doc.id,
      title: doc.title,
      department: doc.department,
      classification: doc.classification,
      type: doc.type,
      content: `[Simulated content of "${doc.title}"] Lorem ipsum dolor sit amet...`,
      owner: users[doc.owner] ? users[doc.owner].name : doc.owner,
      createdAt: doc.createdAt,
    },
    policyDecision: {
      reason: req.abacDecision.reason,
      matchedPolicies: req.abacDecision.matchedPolicies,
    },
  });
});

/**
 * PUT /documents/:docId - Update a document
 * ABAC policy evaluation: action = 'write'
 */
app.put('/documents/:docId', authenticate, abacCheck('write'), (req, res) => {
  const doc = req.abacResource;
  const { title, content } = req.body || {};

  res.json({
    message: `Access granted! You updated "${doc.title}".`,
    updatedFields: {
      title: title || doc.title,
      content: content || '[unchanged]',
    },
    policyDecision: {
      reason: req.abacDecision.reason,
    },
  });
});

/**
 * DELETE /documents/:docId - Delete a document
 * ABAC policy evaluation: action = 'delete'
 */
app.delete('/documents/:docId', authenticate, abacCheck('delete'), (req, res) => {
  const doc = req.abacResource;

  res.json({
    message: `Access granted! Document "${doc.title}" has been deleted.`,
    policyDecision: {
      reason: req.abacDecision.reason,
    },
  });
});

/**
 * POST /evaluate - Manually test policy evaluation
 *
 * This endpoint lets you test the policy engine with arbitrary attributes
 * without needing to be logged in as a specific user. Great for debugging
 * and understanding how policies work.
 *
 * Body: {
 *   "userId": "user1",      // or custom subject attributes
 *   "documentId": "doc1",   // or custom resource attributes
 *   "action": "read",
 *   "environment": { "hour": 10, "dayOfWeek": 3, "clientIp": "192.168.1.50" }
 * }
 */
app.post('/evaluate', (req, res) => {
  const { userId, documentId, action, environment: envOverrides } = req.body;

  if (!userId || !documentId || !action) {
    return res.status(400).json({
      error: 'Missing required fields',
      required: { userId: 'string', documentId: 'string', action: 'string (read/write/delete)' },
      optional: { environment: { hour: 'number (0-23)', dayOfWeek: 'number (0-6)', clientIp: 'string' } },
      availableUsers: Object.keys(users),
      availableDocuments: Object.keys(documents),
    });
  }

  const subject = users[userId];
  if (!subject) {
    return res.status(400).json({ error: 'User not found', availableUsers: Object.keys(users) });
  }

  const resource = documents[documentId];
  if (!resource) {
    return res.status(400).json({ error: 'Document not found', availableDocuments: Object.keys(documents) });
  }

  // Build environment with overrides
  const now = new Date();
  const hour = envOverrides && envOverrides.hour !== undefined ? envOverrides.hour : now.getHours();
  const dayOfWeek = envOverrides && envOverrides.dayOfWeek !== undefined ? envOverrides.dayOfWeek : now.getDay();
  const clientIp = envOverrides && envOverrides.clientIp ? envOverrides.clientIp : '192.168.1.100';

  const isBusinessHours = hour >= BUSINESS_HOURS.start &&
    hour < BUSINESS_HOURS.end &&
    BUSINESS_HOURS.workDays.includes(dayOfWeek);
  const isOfficeNetwork = TRUSTED_NETWORKS.office.some(prefix => clientIp.startsWith(prefix));
  const isVpnNetwork = TRUSTED_NETWORKS.vpn.some(prefix => clientIp.startsWith(prefix));

  const environment = {
    hour,
    dayOfWeek,
    isBusinessHours,
    clientIp,
    isOfficeNetwork,
    isVpnNetwork,
    isTrustedNetwork: isOfficeNetwork || isVpnNetwork,
  };

  const decision = evaluateAccess(subject, resource, action, environment);

  res.json({
    request: {
      subject: { name: subject.name, department: subject.department, clearance: subject.clearanceLevel },
      resource: { title: resource.title, department: resource.department, classification: resource.classification },
      action,
      environment,
    },
    decision: {
      allowed: decision.allowed,
      reason: decision.reason,
      matchedPolicies: decision.matchedPolicies,
    },
  });
});

// =============================================================================
// SECTION 7: Error Handling
// =============================================================================

app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Route ${req.method} ${req.path} does not exist.`,
    hint: 'Visit GET / for available endpoints.',
  });
});

app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message,
  });
});

// =============================================================================
// SECTION 8: Start Server
// =============================================================================

app.listen(PORT, () => {
  console.log('============================================================');
  console.log('  ABAC (Attribute-Based Access Control) Demo Server');
  console.log(`  Running on http://localhost:${PORT}`);
  console.log('============================================================');
  console.log('');
  console.log('Policy Engine: Deny Overrides strategy');
  console.log(`Total Policies: ${policies.length} (${policies.filter(p => p.effect === 'deny').length} deny, ${policies.filter(p => p.effect === 'allow').length} allow)`);
  console.log('');
  console.log('Policies:');
  for (const p of policies.sort((a, b) => b.priority - a.priority)) {
    console.log(`  [${p.effect.toUpperCase().padEnd(5)}] (pri:${p.priority}) ${p.name}`);
    console.log(`          ${p.description}`);
  }
  console.log('');
  console.log('Test Users:');
  for (const user of Object.values(users)) {
    console.log(`  ${user.id}: ${user.name} (${user.department}, clearance: ${user.clearanceLevel})`);
  }
  console.log('');
  console.log('Documents:');
  for (const doc of Object.values(documents)) {
    console.log(`  ${doc.id}: "${doc.title}" (${doc.department}, ${doc.classification})`);
  }
  console.log('');
  console.log('Simulation Headers:');
  console.log('  X-Simulated-Hour: 10    (business hours)');
  console.log('  X-Simulated-Hour: 22    (after hours)');
  console.log('  X-Simulated-Day: 0      (Sunday)');
  console.log('  X-Simulated-IP: 192.168.1.50  (office network)');
  console.log('  X-Simulated-IP: 8.8.8.8       (external network)');
  console.log('');
  console.log('Quick Start:');
  console.log('  1. POST /login with { "userId": "user2" } (HR Director)');
  console.log('  2. GET /documents/doc3 (Employee Salary Database - confidential, HR dept)');
  console.log('  3. Try with X-Simulated-Hour: 22 to see time-based denial');
  console.log('  4. GET /me/access-matrix to see all your access at once');
  console.log('============================================================');
});
