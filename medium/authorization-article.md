# Authorization Explained: RBAC, ABAC, ACL & How to Choose the Right Model

You've verified who the user is (authentication). Now comes the harder question: **what are they allowed to do?** This is authorization — and getting it wrong can mean security breaches, data leaks, or frustrated users who can't access what they need.

Authorization is the invisible architecture behind every "403 Forbidden" response, every grayed-out button, every permission denied error. It determines whether a logged-in user can read a file, delete a record, approve a transaction, or manage other users.

In this guide, we'll explore the major authorization models, compare them side by side, and help you choose the right one for your application.

---

## Authentication vs Authorization

Before we go further, let's make the distinction crystal clear:

| | Authentication | Authorization |
|---|---|---|
| **Question answered** | "Who are you?" | "What can you do?" |
| **Happens** | First | Second (after authentication) |
| **Mechanism** | Passwords, tokens, biometrics | Roles, policies, permissions |
| **HTTP error** | 401 Unauthorized | 403 Forbidden |
| **Example** | Logging into Gmail | Whether you can access someone else's inbox |
| **Analogy** | Showing your ID at the airport | Your boarding pass determining which gate you enter |

Think of it this way: **Authentication is the lock on the front door. Authorization is what rooms you're allowed to enter once you're inside.**

A common mistake is conflating the two. You can have perfect authentication (you know exactly who the user is) but terrible authorization (everyone has admin access). Or vice versa.

```
Request: DELETE /api/users/42

Step 1 - Authentication: "Is this request from a valid, logged-in user?"
  → Yes, this is user "alice@example.com" (verified via JWT)

Step 2 - Authorization: "Is alice@example.com allowed to delete user 42?"
  → Check alice's role: "editor"
  → Editors cannot delete users
  → 403 Forbidden
```

---

## 1. Role-Based Access Control (RBAC)

**RBAC** is the most widely used authorization model. The concept is simple: instead of assigning permissions directly to users, you assign users to **roles**, and roles have **permissions**.

### How RBAC Works

The RBAC model has three key concepts:

1. **Users** — The people or systems that need access
2. **Roles** — Named collections of permissions (e.g., "admin", "editor", "viewer")
3. **Permissions** — Specific actions on specific resources (e.g., "delete:users", "read:reports")

Users are assigned to roles. Roles are assigned permissions. Users inherit all permissions of their assigned roles.

```
User: Alice
  └── Role: Editor
        ├── Permission: read:articles
        ├── Permission: create:articles
        ├── Permission: update:articles (own)
        └── Permission: delete:articles (own)

User: Bob
  └── Role: Admin
        ├── Permission: read:articles
        ├── Permission: create:articles
        ├── Permission: update:articles (all)
        ├── Permission: delete:articles (all)
        ├── Permission: manage:users
        └── Permission: manage:settings
```

### The Model

> **Architecture Diagram: RBAC Model**
> *Reference: diagrams/rbac-model.svg*
>
> ```
>  ┌──────────┐      ┌──────────┐      ┌──────────────┐
>  │  Users   │──M:N─│  Roles   │──M:N─│ Permissions   │
>  └──────────┘      └──────────┘      └──────────────┘
>
>  Alice ─────── Editor ─────── read:articles
>                       ─────── create:articles
>                       ─────── update:articles (own)
>
>  Bob ───────── Admin ──────── read:articles
>                       ─────── create:articles
>                       ─────── update:articles (all)
>                       ─────── delete:articles (all)
>                       ─────── manage:users
>
>  Carol ────── Viewer ──────── read:articles
> ```

### Role Hierarchies

In many RBAC implementations, roles form a hierarchy where higher roles inherit permissions from lower ones:

```
Super Admin
  └── Admin
        └── Manager
              └── Editor
                    └── Viewer
```

A Manager automatically has all permissions of Editor and Viewer, plus their own additional permissions.

### Real-World Examples

**GitHub Repository Roles:**
- **Owner**: Full control — transfer, delete, manage all settings
- **Admin**: Manage settings, branches, webhooks, collaborators
- **Maintainer**: Manage issues, PRs, merge code (no destructive settings)
- **Write (Collaborator)**: Push code, create branches, manage issues
- **Triage**: Manage issues and PRs (no code push)
- **Read**: View code, issues, PRs

**Stripe Dashboard Roles:**
- **Administrator**: Full access to everything
- **Developer**: API keys, webhooks, logs
- **Analyst**: View reports and analytics
- **Support Specialist**: View and refund payments
- **View Only**: Read-only access

**AWS IAM Managed Policies:**
- `AdministratorAccess`: Full access to all AWS services
- `PowerUserAccess`: Full access except IAM management
- `ReadOnlyAccess`: View-only access to all services
- `AmazonS3FullAccess`: Full access to S3 only

### Implementation Pattern

Here's how RBAC is typically implemented:

**Database schema:**

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  name VARCHAR(255) NOT NULL
);

CREATE TABLE roles (
  id UUID PRIMARY KEY,
  name VARCHAR(100) UNIQUE NOT NULL,
  description TEXT
);

CREATE TABLE permissions (
  id UUID PRIMARY KEY,
  action VARCHAR(100) NOT NULL,    -- 'read', 'create', 'update', 'delete'
  resource VARCHAR(100) NOT NULL,  -- 'articles', 'users', 'settings'
  UNIQUE(action, resource)
);

CREATE TABLE user_roles (
  user_id UUID REFERENCES users(id),
  role_id UUID REFERENCES roles(id),
  PRIMARY KEY (user_id, role_id)
);

CREATE TABLE role_permissions (
  role_id UUID REFERENCES roles(id),
  permission_id UUID REFERENCES permissions(id),
  PRIMARY KEY (role_id, permission_id)
);
```

**Middleware:**

```javascript
// Express.js RBAC middleware
function requirePermission(action, resource) {
  return async (req, res, next) => {
    const userId = req.user.id; // Set by authentication middleware

    // Query: Does this user have a role that includes this permission?
    const hasPermission = await db.query(`
      SELECT 1 FROM user_roles ur
      JOIN role_permissions rp ON ur.role_id = rp.role_id
      JOIN permissions p ON rp.permission_id = p.id
      WHERE ur.user_id = $1
        AND p.action = $2
        AND p.resource = $3
      LIMIT 1
    `, [userId, action, resource]);

    if (hasPermission.rows.length === 0) {
      return res.status(403).json({
        error: 'Forbidden',
        message: `You don't have ${action} permission on ${resource}`
      });
    }

    next();
  };
}

// Usage
app.get('/api/articles', requirePermission('read', 'articles'), getArticles);
app.post('/api/articles', requirePermission('create', 'articles'), createArticle);
app.delete('/api/users/:id', requirePermission('delete', 'users'), deleteUser);
```

**JWT with roles:**

```json
{
  "sub": "user-123",
  "email": "alice@example.com",
  "roles": ["editor"],
  "permissions": ["read:articles", "create:articles", "update:articles"],
  "iat": 1679900000,
  "exp": 1679903600
}
```

### Pros & Cons

| Pros | Cons |
|------|------|
| Simple to understand and implement | Can lead to "role explosion" in complex systems |
| Easy to audit ("who has admin access?") | Not granular enough for resource-level control |
| Well-suited for organizational hierarchies | Difficult to express "own resource only" rules |
| Reduces administrative overhead | Doesn't consider context (time, location, etc.) |
| Widely supported by frameworks and tools | Users needing special permissions may require new roles |
| Easy to onboard — assign a role and done | Static — permissions don't change based on conditions |

### When to Use RBAC

- **Most applications** — RBAC is the right default choice
- **Team-based tools** (project management, CMS, dashboards)
- **SaaS products** with clear user tiers (free, pro, enterprise)
- **Enterprise applications** with organizational hierarchies
- When you have a **manageable number of distinct roles** (fewer than 20-30)

---

## 2. Attribute-Based Access Control (ABAC)

**ABAC** is a more flexible and powerful authorization model. Instead of assigning static roles, access decisions are based on **attributes** — properties of the user, the resource, the action, and the environment.

ABAC answers: "Given the attributes of the requester, the resource, and the current context, should this action be allowed?"

### How ABAC Works

ABAC evaluates **policies** against **attributes** from four categories:

1. **Subject attributes**: Properties of the user (department, clearance level, job title, location)
2. **Resource attributes**: Properties of the resource being accessed (classification, owner, creation date)
3. **Action attributes**: The operation being performed (read, write, delete, approve)
4. **Environment attributes**: Contextual information (time of day, IP address, device type)

### A Simple Example

Instead of "editors can edit articles," ABAC lets you express:

> "A user can edit an article if they are in the same department as the article's author, during business hours (9am-6pm), from a corporate IP address, and the article's status is 'draft'."

This single policy involves attributes from all four categories:
- **Subject**: user.department
- **Resource**: article.author.department, article.status
- **Action**: edit
- **Environment**: currentTime, request.ipAddress

### Policy Structure

ABAC policies are typically expressed as rules:

```json
{
  "id": "policy-001",
  "description": "Department members can edit draft articles in their department during business hours",
  "effect": "allow",
  "target": {
    "action": "edit",
    "resource_type": "article"
  },
  "conditions": {
    "all": [
      { "subject.department": { "equals": "resource.department" } },
      { "resource.status": { "equals": "draft" } },
      { "environment.time": { "between": ["09:00", "18:00"] } },
      { "environment.ip": { "in_cidr": "10.0.0.0/8" } }
    ]
  }
}
```

### The Model

> **Architecture Diagram: ABAC Decision Flow**
> *Reference: diagrams/abac-model.svg*
>
> ```
>                    ┌─────────────────────┐
>                    │   Access Request     │
>                    │  (subject, action,   │
>                    │   resource, env)     │
>                    └─────────┬───────────┘
>                              │
>                              ▼
>   ┌────────────┐   ┌─────────────────┐   ┌────────────────┐
>   │  Subject   │──>│  Policy Engine  │<──│   Resource     │
>   │ Attributes │   │                 │   │  Attributes    │
>   └────────────┘   │  Evaluate all   │   └────────────────┘
>                    │  matching       │
>   ┌────────────┐   │  policies       │   ┌────────────────┐
>   │  Action    │──>│                 │<──│  Environment   │
>   │ Attributes │   │  → ALLOW        │   │  Attributes    │
>   └────────────┘   │  → DENY         │   └────────────────┘
>                    └─────────────────┘
> ```

### Real-World ABAC: AWS IAM Policies

AWS IAM is one of the best-known ABAC implementations. Here's an IAM policy that demonstrates ABAC:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::company-data/*",
      "Condition": {
        "StringEquals": {
          "s3:ExistingObjectTag/department": "${aws:PrincipalTag/department}"
        },
        "IpAddress": {
          "aws:SourceIp": "203.0.113.0/24"
        },
        "DateGreaterThan": {
          "aws:CurrentTime": "2024-01-01T00:00:00Z"
        }
      }
    }
  ]
}
```

This policy says: "Allow S3 GetObject if the object's department tag matches the user's department tag, the request comes from the corporate IP range, and the current date is after January 1, 2024."

### XACML (eXtensible Access Control Markup Language)

XACML is the formal standard for ABAC. It defines:

- **PEP (Policy Enforcement Point)**: Where access decisions are enforced (API gateway, middleware)
- **PDP (Policy Decision Point)**: Where access decisions are made (policy engine)
- **PIP (Policy Information Point)**: Where attributes are retrieved from (user directory, databases)
- **PAP (Policy Administration Point)**: Where policies are managed (admin console)

### Implementation Pattern

```javascript
// ABAC policy engine (simplified)
class ABACEngine {
  constructor() {
    this.policies = [];
  }

  addPolicy(policy) {
    this.policies.push(policy);
  }

  evaluate(subject, action, resource, environment) {
    // Find all matching policies
    const matchingPolicies = this.policies.filter(policy => {
      return policy.target.action === action
          && policy.target.resource_type === resource.type;
    });

    // Evaluate conditions
    for (const policy of matchingPolicies) {
      const conditionsMet = policy.conditions.every(condition => {
        return this.evaluateCondition(condition, {
          subject, action, resource, environment
        });
      });

      if (conditionsMet) {
        return policy.effect; // 'allow' or 'deny'
      }
    }

    return 'deny'; // Default deny
  }

  evaluateCondition(condition, context) {
    const { attribute, operator, value } = condition;
    const actualValue = this.resolveAttribute(attribute, context);
    const expectedValue = this.resolveAttribute(value, context);

    switch (operator) {
      case 'equals': return actualValue === expectedValue;
      case 'not_equals': return actualValue !== expectedValue;
      case 'in': return expectedValue.includes(actualValue);
      case 'between': return actualValue >= expectedValue[0]
                          && actualValue <= expectedValue[1];
      default: return false;
    }
  }

  resolveAttribute(path, context) {
    return path.split('.').reduce((obj, key) => obj?.[key], context);
  }
}

// Usage
const engine = new ABACEngine();

engine.addPolicy({
  target: { action: 'edit', resource_type: 'document' },
  effect: 'allow',
  conditions: [
    { attribute: 'subject.department', operator: 'equals', value: 'resource.department' },
    { attribute: 'resource.status', operator: 'equals', value: 'draft' },
    { attribute: 'environment.hour', operator: 'between', value: [9, 18] }
  ]
});

const decision = engine.evaluate(
  { id: 'alice', department: 'engineering', clearance: 'high' },  // subject
  'edit',                                                          // action
  { type: 'document', department: 'engineering', status: 'draft' },// resource
  { hour: 14, ip: '10.0.1.50' }                                   // environment
);

console.log(decision); // 'allow'
```

### Pros & Cons

| Pros | Cons |
|------|------|
| Extremely granular and flexible | Complex to implement and maintain |
| Context-aware decisions | Policies can become hard to understand |
| No "role explosion" — scales with attributes | Debugging access issues is difficult |
| Can express complex real-world rules | Performance overhead from policy evaluation |
| Dynamic — decisions change with context | Requires rich attribute data from multiple sources |
| Powerful for compliance requirements | Steeper learning curve for administrators |

### When to Use ABAC

- **Complex authorization requirements** that can't be expressed with simple roles
- **Multi-tenant systems** where access depends on organizational context
- **Data classification** environments (government, healthcare, finance)
- **When rules depend on context** (time, location, device, data sensitivity)
- **Large organizations** where managing hundreds of roles becomes impractical
- **Compliance-heavy industries** (HIPAA, SOX, GDPR) requiring fine-grained audit trails

---

## 3. Access Control Lists (ACL)

**ACL (Access Control List)** is one of the oldest and most intuitive authorization models. It attaches a list of permissions directly to each resource, specifying which users or groups can perform which actions.

If RBAC is "what can this user do?", ACL is "who can access this resource?"

### How ACL Works

Every resource maintains a list of entries, where each entry specifies:
- **Who** (a user or group)
- **What they can do** (read, write, execute, share, etc.)

```
Document: "Q4 Financial Report.pdf"
  ACL:
    ├── alice@example.com     → [read, write, share]
    ├── bob@example.com       → [read]
    ├── finance-team@group    → [read, write]
    └── everyone@public       → [no access]
```

### The Model

> **Architecture Diagram: ACL Model**
> *Reference: diagrams/acl-model.svg*
>
> ```
>  Resource: "Project Plan.docx"
>  ┌──────────────────────────────────────────┐
>  │ Access Control List                       │
>  │                                           │
>  │  Principal          │ Permissions         │
>  │  ─────────────────  │ ─────────────────── │
>  │  alice@example.com  │ read, write, share  │
>  │  bob@example.com    │ read                │
>  │  engineering@group  │ read, write         │
>  │  public             │ (none)              │
>  └──────────────────────────────────────────┘
>
>  Resource: "logo.png"
>  ┌──────────────────────────────────────────┐
>  │ Access Control List                       │
>  │                                           │
>  │  Principal          │ Permissions         │
>  │  ─────────────────  │ ─────────────────── │
>  │  design@group       │ read, write         │
>  │  everyone           │ read                │
>  └──────────────────────────────────────────┘
> ```

### Real-World Example: Google Drive

Google Drive is a perfect example of ACL in action:

- When you share a document, you're modifying its ACL
- You can share with specific people (alice@gmail.com → Editor)
- You can share with groups (marketing@company.com → Viewer)
- You can set "Anyone with the link" (public → Viewer)
- Each permission level maps to specific capabilities:
  - **Owner**: Full control, can delete, can transfer ownership
  - **Editor**: Read, write, comment, format
  - **Commenter**: Read, comment only
  - **Viewer**: Read only

### File System Permissions (Unix ACL)

Unix/Linux file permissions are a classic ACL implementation:

```bash
$ ls -la document.txt
-rw-r--r-- 1 alice engineering 4096 Mar 15 10:00 document.txt

# Breakdown:
# Owner (alice):       rw-  (read, write)
# Group (engineering): r--  (read only)
# Others:              r--  (read only)
```

Extended ACLs provide more granularity:

```bash
# Set ACL: give bob read+write access
$ setfacl -m u:bob:rw document.txt

# View ACL
$ getfacl document.txt
# file: document.txt
# owner: alice
# group: engineering
user::rw-
user:bob:rw-
group::r--
mask::rw-
other::r--
```

### Implementation Pattern

```javascript
// Database schema for ACL
// Each resource has a list of access control entries (ACEs)

// SQL Schema
/*
CREATE TABLE resources (
  id UUID PRIMARY KEY,
  name VARCHAR(255),
  type VARCHAR(50),
  owner_id UUID REFERENCES users(id)
);

CREATE TABLE access_control_entries (
  id UUID PRIMARY KEY,
  resource_id UUID REFERENCES resources(id),
  principal_type VARCHAR(20),   -- 'user', 'group', 'public'
  principal_id UUID,            -- user_id or group_id
  permission VARCHAR(50),       -- 'read', 'write', 'delete', 'share', 'admin'
  granted_by UUID REFERENCES users(id),
  granted_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(resource_id, principal_type, principal_id, permission)
);
*/

// ACL Middleware
async function checkACL(action) {
  return async (req, res, next) => {
    const resourceId = req.params.resourceId;
    const userId = req.user.id;
    const userGroups = req.user.groups; // ['engineering', 'project-alpha']

    // Check if user has direct permission
    const directAccess = await db.query(`
      SELECT 1 FROM access_control_entries
      WHERE resource_id = $1
        AND principal_type = 'user'
        AND principal_id = $2
        AND permission = $3
    `, [resourceId, userId, action]);

    if (directAccess.rows.length > 0) {
      return next();
    }

    // Check group permissions
    const groupAccess = await db.query(`
      SELECT 1 FROM access_control_entries
      WHERE resource_id = $1
        AND principal_type = 'group'
        AND principal_id = ANY($2)
        AND permission = $3
    `, [resourceId, userGroups, action]);

    if (groupAccess.rows.length > 0) {
      return next();
    }

    // Check public access
    const publicAccess = await db.query(`
      SELECT 1 FROM access_control_entries
      WHERE resource_id = $1
        AND principal_type = 'public'
        AND permission = $2
    `, [resourceId, action]);

    if (publicAccess.rows.length > 0) {
      return next();
    }

    return res.status(403).json({ error: 'Access denied' });
  };
}

// Usage
app.get('/api/documents/:resourceId', checkACL('read'), getDocument);
app.put('/api/documents/:resourceId', checkACL('write'), updateDocument);
app.delete('/api/documents/:resourceId', checkACL('delete'), deleteDocument);

// Sharing (modifying the ACL)
app.post('/api/documents/:resourceId/share', checkACL('share'), async (req, res) => {
  const { email, permission } = req.body;
  const user = await findUserByEmail(email);

  await db.query(`
    INSERT INTO access_control_entries (resource_id, principal_type, principal_id, permission, granted_by)
    VALUES ($1, 'user', $2, $3, $4)
    ON CONFLICT DO NOTHING
  `, [req.params.resourceId, user.id, permission, req.user.id]);

  res.json({ message: `Shared with ${email} as ${permission}` });
});
```

### Pros & Cons

| Pros | Cons |
|------|------|
| Intuitive — users understand sharing | Doesn't scale well with many resources |
| Per-resource granularity | Hard to answer "what can this user access?" |
| Users can manage their own sharing | Permission sprawl over time |
| Maps well to file/document systems | No context awareness (time, location) |
| Easy to implement for small systems | Difficult to audit at an organizational level |
| Familiar UX (sharing dialogs) | Every resource needs its own ACL managed |

### When to Use ACL

- **Document and file management** systems (Google Drive, Dropbox, SharePoint)
- **Collaboration tools** where users share resources with each other
- **Content management** where individual items need unique access rules
- **Any system where sharing is a core feature**
- When access patterns are **resource-centric** rather than role-centric

---

## 4. Delegated Authorization with OAuth 2.0

We covered OAuth 2.0 as an authentication mechanism in the companion article, but it's fundamentally an **authorization framework**. OAuth 2.0's primary purpose is to grant third-party applications limited access to a user's resources.

### OAuth 2.0 as Authorization

The key authorization concept in OAuth 2.0 is **scopes**. Scopes define the specific permissions a client application is requesting:

```
https://accounts.google.com/o/oauth2/v2/auth?
  scope=https://www.googleapis.com/auth/drive.readonly
        https://www.googleapis.com/auth/calendar.events
```

This requests:
- **Read-only** access to Google Drive (can't modify or delete files)
- Access to Google Calendar **events** (but not settings or other calendar data)

### Common OAuth 2.0 Scopes

**GitHub:**
- `repo` — Full control of repositories
- `repo:status` — Read/write commit statuses
- `read:org` — Read organization data
- `admin:org` — Full organization management
- `gist` — Create gists

**Google:**
- `openid` — User's identity
- `profile` — Basic profile info
- `email` — Email address
- `https://www.googleapis.com/auth/drive.readonly` — Read Drive files
- `https://www.googleapis.com/auth/calendar` — Manage Calendar

**Slack:**
- `channels:read` — View channel info
- `chat:write` — Send messages
- `users:read` — View user info
- `files:write` — Upload files

### The Authorization Decision

When a user sees the OAuth consent screen, they are making an **authorization decision**:

```
"PrintService is requesting access to your Google account:"

☑ View your Google Photos (photos.readonly)
☑ View your basic profile info (profile)
☐ Manage your Google Drive files (drive)  ← User can deselect

[Allow]  [Deny]
```

The user controls exactly what permissions the application receives. This is delegated authorization — the user delegates a subset of their permissions to a third-party application.

### Checking Scopes in Your API

```javascript
// Middleware to verify OAuth scopes
function requireScope(...requiredScopes) {
  return (req, res, next) => {
    const tokenScopes = req.token.scope.split(' '); // From the access token

    const hasAllScopes = requiredScopes.every(scope =>
      tokenScopes.includes(scope)
    );

    if (!hasAllScopes) {
      return res.status(403).json({
        error: 'insufficient_scope',
        required: requiredScopes,
        provided: tokenScopes
      });
    }

    next();
  };
}

// Usage
app.get('/api/photos', requireScope('photos.read'), listPhotos);
app.post('/api/photos', requireScope('photos.write'), uploadPhoto);
app.delete('/api/photos/:id', requireScope('photos.delete'), deletePhoto);
```

---

## 5. Token-Based Authorization

JWTs and other tokens don't just carry authentication information — they carry **authorization claims**. This allows servers to make authorization decisions without querying a database.

### Authorization Claims in JWTs

A well-designed JWT includes authorization information:

```json
{
  "sub": "user-456",
  "email": "alice@example.com",
  "roles": ["editor", "billing-admin"],
  "permissions": [
    "articles:read",
    "articles:create",
    "articles:update",
    "billing:read",
    "billing:manage"
  ],
  "org_id": "org-789",
  "plan": "enterprise",
  "iat": 1679900000,
  "exp": 1679903600
}
```

This single token tells the server:
- **Who**: alice@example.com (user-456)
- **Roles**: editor and billing-admin
- **Permissions**: Specific actions she can perform
- **Organization**: Which organization she belongs to
- **Plan**: What subscription tier (affects feature access)

### Using JWT Claims for Authorization

```javascript
// Middleware that checks JWT claims
function authorize(requiredPermission) {
  return (req, res, next) => {
    const { permissions, roles, plan } = req.user; // Decoded from JWT

    // Check direct permission
    if (permissions.includes(requiredPermission)) {
      return next();
    }

    // Check if any role grants this permission
    const rolePermissions = getRolePermissions(roles);
    if (rolePermissions.includes(requiredPermission)) {
      return next();
    }

    return res.status(403).json({ error: 'Insufficient permissions' });
  };
}

// Feature flagging based on plan
function requirePlan(...allowedPlans) {
  return (req, res, next) => {
    if (!allowedPlans.includes(req.user.plan)) {
      return res.status(403).json({
        error: 'Upgrade required',
        message: `This feature requires one of: ${allowedPlans.join(', ')}`,
        current_plan: req.user.plan
      });
    }
    next();
  };
}

// Combined usage
app.post('/api/reports/export',
  requirePlan('pro', 'enterprise'),
  authorize('reports:export'),
  exportReport
);
```

### The Trade-off: Token Size vs Database Queries

| Approach | Pros | Cons |
|----------|------|------|
| **Everything in the JWT** | No DB queries, fast | Token grows large, stale data |
| **Minimal JWT + DB lookup** | Always current, small token | DB query on every request |
| **Hybrid** (roles in JWT, check DB for sensitive ops) | Balanced | More complex logic |

The hybrid approach is the most common in production:

```javascript
// Fast path: Check JWT claims (no DB)
app.get('/api/articles', authorize('articles:read'), listArticles);

// Slow path: Check DB for sensitive operations
app.delete('/api/users/:id', async (req, res) => {
  // Verify current permissions from DB (not just token)
  const currentUser = await db.users.findById(req.user.sub);
  const currentPermissions = await getPermissionsFromDB(currentUser);

  if (!currentPermissions.includes('users:delete')) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  // Proceed with deletion
});
```

---

## Combining Models: Real-World Architectures

In practice, most production systems combine multiple authorization models. Here's how some well-known platforms do it:

### GitHub: RBAC + Resource-Level Permissions

GitHub uses a layered approach:

1. **Organization level**: RBAC (Owner, Member, Billing Manager)
2. **Team level**: RBAC (Maintainer, Member)
3. **Repository level**: RBAC (Admin, Maintain, Write, Triage, Read)
4. **Branch level**: Rules (branch protection = ABAC-like conditions)
5. **Fine-grained tokens**: Scoped permissions (OAuth/token-based)

```
Organization: "Acme Corp"
  ├── Role: Owner → full org control
  ├── Team: "Backend"
  │     ├── Role: Maintainer → manage team settings
  │     └── Repo: "api-server" → Write access
  ├── Team: "Frontend"
  │     └── Repo: "web-app" → Write access
  └── Branch Protection (on main):
        ├── Require 2 approving reviews
        ├── Require status checks to pass
        └── Restrict who can push (ABAC-like)
```

### Google Drive: ACL + RBAC

Google Drive combines:
- **ACL** for individual file sharing (alice@gmail.com → Editor)
- **RBAC** for organizational controls (Google Workspace admin roles)
- **Hierarchical inheritance** (folder permissions cascade to contents)
- **Link sharing** (public ACL entry)

### AWS IAM: RBAC + ABAC

AWS combines both models in a sophisticated way:
- **RBAC**: IAM roles and managed policies
- **ABAC**: Policy conditions based on tags, IP, time, MFA status
- **Resource-based policies**: Like ACLs on S3 buckets, SQS queues
- **Service Control Policies**: Organizational boundaries
- **Permission boundaries**: Limiting maximum permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ec2:StartInstances", "ec2:StopInstances"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ec2:ResourceTag/Environment": "${aws:PrincipalTag/Environment}",
          "ec2:ResourceTag/Project": "${aws:PrincipalTag/Project}"
        }
      }
    }
  ]
}
```

This is pure ABAC: users can only manage EC2 instances that share their Environment and Project tags.

### Firebase: Rule-Based (RBAC + ABAC Hybrid)

Firebase Security Rules are a unique blend:

```javascript
// Firebase Firestore Security Rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // RBAC: Only admins can manage users
    match /users/{userId} {
      allow read: if request.auth != null;
      allow write: if get(/databases/$(database)/documents/users/$(request.auth.uid))
                      .data.role == 'admin';
    }

    // ACL: Users can only access their own documents
    match /documents/{docId} {
      allow read: if request.auth.uid in resource.data.sharedWith
                  || request.auth.uid == resource.data.ownerId;
      allow write: if request.auth.uid == resource.data.ownerId;
    }

    // ABAC: Time-based and attribute-based conditions
    match /reports/{reportId} {
      allow read: if request.auth != null
                  && resource.data.department == request.auth.token.department
                  && request.time < resource.data.expiresAt;
    }
  }
}
```

---

## Comparison Table

| Model | Granularity | Complexity | Scalability | Dynamic | Best For |
|-------|-------------|------------|-------------|---------|----------|
| **RBAC** | Role-level | Low | Good for < 30 roles | No | Most apps, team tools, SaaS |
| **ABAC** | Attribute-level | High | Excellent | Yes | Enterprise, compliance, complex rules |
| **ACL** | Resource-level | Medium | Per-resource | Partially | File systems, sharing, collaboration |
| **OAuth Scopes** | Scope-level | Medium | Good | No | Third-party API access |
| **JWT Claims** | Claim-level | Low | Stateless | No (until expiry) | Microservices, APIs |

### When Each Model Shines

| Scenario | Recommended Model |
|----------|-------------------|
| "Admin, Editor, Viewer" permissions | RBAC |
| "Users can share documents with others" | ACL |
| "Access depends on department + time + location" | ABAC |
| "Third-party apps need limited access" | OAuth Scopes |
| "Microservices need to check permissions without DB calls" | JWT Claims |
| "Enterprise with 100+ fine-grained permission rules" | ABAC or RBAC + ABAC hybrid |

---

## Decision Tree: Which Authorization Model Should You Choose?

```
START: What's your primary authorization need?
│
├── Simple user tiers (admin/editor/viewer)?
│   └── RBAC
│       └── Need resource-level sharing too?
│           └── RBAC + ACL
│
├── Users sharing resources with each other?
│   └── ACL
│       └── Need organizational roles too?
│           └── ACL + RBAC
│
├── Complex rules based on context (time, location, data classification)?
│   └── ABAC
│       └── Also need simple role groupings?
│           └── RBAC + ABAC (most enterprise systems)
│
├── Third-party applications accessing user data?
│   └── OAuth 2.0 Scopes
│
├── Microservices that need stateless authorization?
│   └── JWT Claims (with RBAC or ABAC encoded)
│
└── Not sure / Building something new?
    └── Start with RBAC (simplest, covers 80% of cases)
        └── Add ACL if users need to share resources
        └── Add ABAC conditions as complexity grows
```

### The 80/20 Rule of Authorization

For most applications:
- **RBAC** handles 80% of your authorization needs
- **ACL** handles the next 15% (resource sharing)
- **ABAC** handles the remaining 5% (complex conditions)

Start simple. Add complexity only when you have a clear need.

---

## Key Takeaways

- **Authorization is separate from authentication.** Verify identity first, then check permissions. Never conflate the two.

- **RBAC is the right default choice** for most applications. It's simple, well-understood, and covers the majority of use cases.

- **ACL is essential for sharing-oriented systems.** If users need to share individual resources with specific people or groups, you need ACLs.

- **ABAC is powerful but complex.** Reserve it for when you genuinely need context-aware, attribute-based decisions. Don't over-engineer.

- **OAuth 2.0 scopes are for delegation**, not internal authorization. Use them when third-party apps need limited access to your users' data.

- **JWTs can carry authorization claims**, enabling stateless permission checks. But remember that JWT claims can become stale — verify from the database for sensitive operations.

- **Most production systems combine models.** GitHub uses RBAC + resource permissions. AWS uses RBAC + ABAC. Google Drive uses ACL + RBAC. Don't feel locked into one model.

- **Start simple, evolve as needed.** Begin with RBAC, add ACL for sharing, introduce ABAC for complex conditions. You can always layer models.

- **Always default to deny.** If no rule explicitly grants access, the answer should be "no." This principle protects against misconfiguration.

- **Audit everything.** Log every authorization decision (especially denials) to detect unauthorized access attempts and debug permission issues.

---

## What's Next?

If you haven't already, check out the companion article on **Authentication** — covering Basic Auth, Bearer Tokens, API Keys, OAuth2, JWT, SSO, and Passkeys.

Read it here: [Authentication Explained: Basic Auth, Bearer Tokens, API Keys, OAuth2, JWT, SSO & Passkeys](#)

Together, these two articles give you a complete picture of how to secure modern applications from end to end.

---

## References

- NIST RBAC Model: [SP 800-162](https://csrc.nist.gov/publications/detail/sp/800-162/final)
- XACML Standard: [OASIS XACML 3.0](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html)
- OAuth 2.0 Scopes: [RFC 6749 Section 3.3](https://tools.ietf.org/html/rfc6749#section-3.3)
- AWS IAM ABAC: [AWS Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/introduction_attribute-based-access-control.html)
- Google Drive Sharing: [Google Workspace Admin Help](https://support.google.com/a/answer/60781)
- Full code implementations: [GitHub Repository](https://github.com/vineetpanwar/AuthenticationAndAuthorization)

---

*If you found this guide helpful, follow me for more deep dives into security, backend architecture, and developer tools.*
