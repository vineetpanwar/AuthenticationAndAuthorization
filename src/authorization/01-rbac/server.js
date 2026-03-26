/**
 * ============================================================================
 * ROLE-BASED ACCESS CONTROL (RBAC) - Authorization Server
 * ============================================================================
 *
 * WHAT IS RBAC?
 * Role-Based Access Control restricts system access based on the roles
 * assigned to individual users. Instead of assigning permissions directly
 * to each user, permissions are grouped into roles, and users are assigned
 * one or more roles.
 *
 * HOW IT WORKS:
 *   User -> Role(s) -> Permission(s) -> Access Decision
 *
 * KEY CONCEPTS:
 *   - Role: A named collection of permissions (e.g., "admin", "editor")
 *   - Permission: A specific action on a resource (e.g., "write:articles")
 *   - User-Role Assignment: Mapping users to their roles
 *   - Role-Permission Assignment: Mapping roles to their permissions
 *   - Role Hierarchy: Some roles inherit permissions from others
 *
 * REAL-WORLD EXAMPLES:
 *   - GitHub: Owner, Admin, Maintainer, Collaborator (Write), Triage, Read
 *   - AWS IAM: Roles like AdministratorAccess, ReadOnlyAccess, PowerUser
 *   - WordPress: Super Admin, Administrator, Editor, Author, Contributor, Subscriber
 *   - Jira: Project Admin, Developer, QA, Viewer
 *   - Google Workspace: Super Admin, Groups Admin, User Management Admin, Help Desk Admin
 *
 * PROS:
 *   - Simple to understand and implement
 *   - Easy to audit (who has what role?)
 *   - Scales well for organizations with clear role structures
 *   - Reduces management overhead vs. per-user permissions
 *
 * CONS:
 *   - Can lead to "role explosion" in complex systems
 *   - Not great for fine-grained, context-dependent decisions
 *   - Rigid - doesn't account for attributes like time, location, etc.
 *
 * THIS DEMO:
 *   Implements a GitHub-like repository access model with roles,
 *   permissions, role hierarchy, and protected routes.
 *
 * Port: 3008
 * ============================================================================
 */

const express = require('express');
const app = express();
const PORT = 3008;

app.use(express.json());

// =============================================================================
// SECTION 1: Define the Permission System
// =============================================================================

/**
 * Permissions are granular actions that can be performed.
 * We use a "resource:action" naming convention for clarity.
 */
const PERMISSIONS = {
  // Repository permissions
  'repo:read': 'View repository contents, issues, and pull requests',
  'repo:write': 'Push code, create branches',
  'repo:delete': 'Delete the repository',
  'repo:settings': 'Modify repository settings',

  // Issue permissions
  'issues:read': 'View issues',
  'issues:write': 'Create and edit issues',
  'issues:close': 'Close and reopen issues',
  'issues:assign': 'Assign issues to users',
  'issues:label': 'Add/remove labels on issues',

  // Pull request permissions
  'pr:read': 'View pull requests',
  'pr:write': 'Create pull requests',
  'pr:merge': 'Merge pull requests',
  'pr:review': 'Approve or request changes on pull requests',

  // Team/member management
  'members:read': 'View team members',
  'members:invite': 'Invite new members',
  'members:remove': 'Remove members from the repository',
  'members:change_role': 'Change a member\'s role',

  // Admin
  'admin:audit_log': 'View the audit log',
  'admin:billing': 'View and manage billing',
};

// =============================================================================
// SECTION 2: Define Roles and their Permissions
// =============================================================================

/**
 * Each role is a named collection of permissions.
 * Roles can also inherit from other roles (role hierarchy).
 *
 * Role Hierarchy (most to least privileged):
 *   owner > admin > maintainer > collaborator > triager > viewer
 *
 * This mirrors GitHub's repository permission levels.
 */
const ROLES = {
  // Viewer - read-only access
  viewer: {
    description: 'Read-only access to the repository',
    inherits: [],
    permissions: [
      'repo:read',
      'issues:read',
      'pr:read',
      'members:read',
    ],
  },

  // Triager - can manage issues but cannot write code
  triager: {
    description: 'Can manage issues and pull requests without write access',
    inherits: ['viewer'],
    permissions: [
      'issues:write',
      'issues:close',
      'issues:assign',
      'issues:label',
    ],
  },

  // Collaborator - can write code
  collaborator: {
    description: 'Can push code and manage pull requests',
    inherits: ['triager'],
    permissions: [
      'repo:write',
      'pr:write',
      'pr:review',
    ],
  },

  // Maintainer - can merge and manage contributors
  maintainer: {
    description: 'Can merge PRs and manage some settings',
    inherits: ['collaborator'],
    permissions: [
      'pr:merge',
      'members:invite',
    ],
  },

  // Admin - full control except billing/ownership
  admin: {
    description: 'Full access to the repository except ownership transfer',
    inherits: ['maintainer'],
    permissions: [
      'repo:settings',
      'repo:delete',
      'members:remove',
      'members:change_role',
      'admin:audit_log',
    ],
  },

  // Owner - complete control
  owner: {
    description: 'Complete control including billing and ownership',
    inherits: ['admin'],
    permissions: [
      'admin:billing',
    ],
  },
};

/**
 * Resolve all permissions for a role, including inherited ones.
 * This recursively walks the inheritance chain to collect every permission.
 *
 * Example: collaborator inherits triager, which inherits viewer.
 * So collaborator gets all viewer + triager + collaborator permissions.
 */
function resolvePermissions(roleName) {
  const role = ROLES[roleName];
  if (!role) return [];

  // Start with the role's own permissions
  let allPermissions = [...role.permissions];

  // Recursively add inherited permissions
  for (const parentRole of role.inherits) {
    allPermissions = allPermissions.concat(resolvePermissions(parentRole));
  }

  // Remove duplicates
  return [...new Set(allPermissions)];
}

// Pre-compute resolved permissions for each role (optimization)
const RESOLVED_PERMISSIONS = {};
for (const roleName of Object.keys(ROLES)) {
  RESOLVED_PERMISSIONS[roleName] = resolvePermissions(roleName);
}

// =============================================================================
// SECTION 3: Seed Data - Users and their Role Assignments
// =============================================================================

/**
 * In production, this would come from a database.
 * Each user has an id, name, email, and one or more roles.
 *
 * A user can have different roles in different contexts (e.g., different repos).
 * Here we use a simple global role assignment for demonstration.
 */
const users = {
  user1: {
    id: 'user1',
    name: 'Alice Chen',
    email: 'alice@example.com',
    role: 'owner',
  },
  user2: {
    id: 'user2',
    name: 'Bob Martinez',
    email: 'bob@example.com',
    role: 'admin',
  },
  user3: {
    id: 'user3',
    name: 'Carol Williams',
    email: 'carol@example.com',
    role: 'maintainer',
  },
  user4: {
    id: 'user4',
    name: 'David Kim',
    email: 'david@example.com',
    role: 'collaborator',
  },
  user5: {
    id: 'user5',
    name: 'Eve Johnson',
    email: 'eve@example.com',
    role: 'triager',
  },
  user6: {
    id: 'user6',
    name: 'Frank Brown',
    email: 'frank@example.com',
    role: 'viewer',
  },
};

// Simple token-to-user mapping (simulates authentication)
// In production, you'd use JWT, sessions, or OAuth tokens
const sessions = {};

// =============================================================================
// SECTION 4: Authorization Middleware
// =============================================================================

/**
 * Middleware: Authenticate the user from the session token.
 * This extracts the user from the Authorization header and attaches
 * them (with their resolved permissions) to req.user.
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
      message: 'Please log in again.',
    });
  }

  // Attach user info and resolved permissions to the request
  req.user = {
    ...session.user,
    permissions: RESOLVED_PERMISSIONS[session.user.role] || [],
  };

  console.log(`[AUTH] Authenticated: ${req.user.name} (role: ${req.user.role})`);
  next();
}

/**
 * Middleware Factory: checkRole
 * Checks if the user has one of the specified roles.
 *
 * Usage: app.get('/admin', authenticate, checkRole('admin', 'owner'), handler)
 *
 * This is a coarse-grained check - useful when you want to restrict
 * an entire route to certain roles.
 */
function checkRole(...allowedRoles) {
  return (req, res, next) => {
    const userRole = req.user.role;

    if (!allowedRoles.includes(userRole)) {
      console.log(
        `[RBAC] DENIED: ${req.user.name} (role: ${userRole}) ` +
        `tried to access route requiring roles: [${allowedRoles.join(', ')}]`
      );
      return res.status(403).json({
        error: 'Forbidden',
        message: `This action requires one of these roles: ${allowedRoles.join(', ')}`,
        yourRole: userRole,
        requiredRoles: allowedRoles,
      });
    }

    console.log(
      `[RBAC] ALLOWED: ${req.user.name} (role: ${userRole}) ` +
      `- role is in allowed list: [${allowedRoles.join(', ')}]`
    );
    next();
  };
}

/**
 * Middleware Factory: checkPermission
 * Checks if the user has ALL of the specified permissions.
 *
 * Usage: app.post('/issues', authenticate, checkPermission('issues:write'), handler)
 *
 * This is more fine-grained than checkRole - it checks specific capabilities
 * rather than role names. This is the PREFERRED approach because:
 *   - It decouples routes from specific role names
 *   - Adding a new role automatically works if permissions are assigned correctly
 *   - It's easier to audit what permissions a route requires
 */
function checkPermission(...requiredPermissions) {
  return (req, res, next) => {
    const userPermissions = req.user.permissions;

    const missing = requiredPermissions.filter(p => !userPermissions.includes(p));

    if (missing.length > 0) {
      console.log(
        `[RBAC] DENIED: ${req.user.name} (role: ${req.user.role}) ` +
        `missing permissions: [${missing.join(', ')}]`
      );
      return res.status(403).json({
        error: 'Forbidden',
        message: 'You do not have the required permissions for this action.',
        requiredPermissions,
        missingPermissions: missing,
        yourRole: req.user.role,
        yourPermissions: userPermissions,
      });
    }

    console.log(
      `[RBAC] ALLOWED: ${req.user.name} (role: ${req.user.role}) ` +
      `has permissions: [${requiredPermissions.join(', ')}]`
    );
    next();
  };
}

/**
 * Middleware Factory: checkAnyPermission
 * Checks if the user has AT LEAST ONE of the specified permissions.
 *
 * Usage: app.get('/items', authenticate, checkAnyPermission('items:read', 'items:write'), handler)
 */
function checkAnyPermission(...permissions) {
  return (req, res, next) => {
    const userPermissions = req.user.permissions;
    const hasAny = permissions.some(p => userPermissions.includes(p));

    if (!hasAny) {
      console.log(
        `[RBAC] DENIED: ${req.user.name} (role: ${req.user.role}) ` +
        `has none of: [${permissions.join(', ')}]`
      );
      return res.status(403).json({
        error: 'Forbidden',
        message: 'You do not have any of the required permissions.',
        requiredOneOf: permissions,
        yourPermissions: userPermissions,
      });
    }

    console.log(
      `[RBAC] ALLOWED: ${req.user.name} (role: ${req.user.role}) ` +
      `has at least one of: [${permissions.join(', ')}]`
    );
    next();
  };
}

// =============================================================================
// SECTION 5: Routes
// =============================================================================

// ---------------------
// Public Routes
// ---------------------

/**
 * GET / - Welcome page with API documentation
 */
app.get('/', (req, res) => {
  res.json({
    title: 'RBAC (Role-Based Access Control) Demo Server',
    port: PORT,
    description: 'GitHub-like repository access model with role hierarchy',
    roles: Object.entries(ROLES).map(([name, role]) => ({
      name,
      description: role.description,
      inherits: role.inherits,
      totalPermissions: RESOLVED_PERMISSIONS[name].length,
    })),
    endpoints: {
      public: {
        'POST /login': 'Log in with { "userId": "user1" } to get a token',
        'GET /roles': 'View all roles and their permissions',
        'GET /roles/:roleName': 'View a specific role\'s permissions',
      },
      protected: {
        'GET /repo': 'View repository (requires repo:read)',
        'POST /repo/push': 'Push code (requires repo:write)',
        'DELETE /repo': 'Delete repository (requires repo:delete)',
        'GET /repo/settings': 'View settings (requires repo:settings)',
        'GET /issues': 'View issues (requires issues:read)',
        'POST /issues': 'Create issue (requires issues:write)',
        'PATCH /issues/:id/close': 'Close issue (requires issues:close)',
        'POST /issues/:id/assign': 'Assign issue (requires issues:assign)',
        'GET /pulls': 'View PRs (requires pr:read)',
        'POST /pulls': 'Create PR (requires pr:write)',
        'POST /pulls/:id/merge': 'Merge PR (requires pr:merge)',
        'POST /pulls/:id/review': 'Review PR (requires pr:review)',
        'GET /members': 'View members (requires members:read)',
        'POST /members/invite': 'Invite member (requires members:invite)',
        'DELETE /members/:id': 'Remove member (requires members:remove)',
        'PATCH /members/:id/role': 'Change role (requires members:change_role)',
        'GET /admin/audit-log': 'View audit log (requires admin:audit_log)',
        'GET /admin/billing': 'View billing (requires admin:billing)',
        'GET /me': 'View your own user info and permissions',
      },
    },
    testUsers: Object.values(users).map(u => ({
      userId: u.id,
      name: u.name,
      role: u.role,
    })),
  });
});

/**
 * POST /login - Simulate user login
 * In production, this would validate credentials and create a JWT.
 * Here we use a simple token for demonstration purposes.
 */
app.post('/login', (req, res) => {
  const { userId } = req.body;

  if (!userId || !users[userId]) {
    return res.status(400).json({
      error: 'Invalid userId',
      message: 'Provide a valid userId in the request body.',
      availableUsers: Object.keys(users).map(id => ({
        userId: id,
        name: users[id].name,
        role: users[id].role,
      })),
    });
  }

  const user = users[userId];
  // Generate a simple token (in production, use JWT or similar)
  const token = `rbac-token-${userId}-${Date.now()}`;

  sessions[token] = {
    user,
    createdAt: new Date().toISOString(),
  };

  console.log(`[LOGIN] ${user.name} logged in as "${user.role}" (token: ${token})`);

  res.json({
    message: `Welcome, ${user.name}! You are logged in as "${user.role}".`,
    token,
    role: user.role,
    permissions: RESOLVED_PERMISSIONS[user.role],
    usage: 'Include this token in the Authorization header for protected routes.',
  });
});

/**
 * GET /roles - View all roles and their permissions
 */
app.get('/roles', (req, res) => {
  const rolesInfo = {};
  for (const [name, role] of Object.entries(ROLES)) {
    rolesInfo[name] = {
      description: role.description,
      inherits: role.inherits,
      ownPermissions: role.permissions,
      allPermissions: RESOLVED_PERMISSIONS[name],
    };
  }
  res.json({ roles: rolesInfo });
});

/**
 * GET /roles/:roleName - View a specific role and its full permission set
 */
app.get('/roles/:roleName', (req, res) => {
  const { roleName } = req.params;
  const role = ROLES[roleName];

  if (!role) {
    return res.status(404).json({
      error: 'Role not found',
      availableRoles: Object.keys(ROLES),
    });
  }

  res.json({
    role: roleName,
    description: role.description,
    inherits: role.inherits,
    ownPermissions: role.permissions,
    allPermissions: RESOLVED_PERMISSIONS[roleName],
    permissionDetails: RESOLVED_PERMISSIONS[roleName].map(p => ({
      permission: p,
      description: PERMISSIONS[p],
    })),
  });
});

// ---------------------
// Protected Routes
// ---------------------

/**
 * GET /me - View current user's info, role, and permissions
 * Any authenticated user can access this.
 */
app.get('/me', authenticate, (req, res) => {
  res.json({
    user: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
    },
    roleDescription: ROLES[req.user.role].description,
    permissions: req.user.permissions,
    permissionDetails: req.user.permissions.map(p => ({
      permission: p,
      description: PERMISSIONS[p],
    })),
  });
});

// --- Repository Routes ---

/**
 * GET /repo - View the repository
 * Requires: repo:read (available to all roles including viewer)
 */
app.get('/repo', authenticate, checkPermission('repo:read'), (req, res) => {
  res.json({
    repository: {
      name: 'awesome-project',
      description: 'An awesome open-source project',
      stars: 1234,
      forks: 567,
      defaultBranch: 'main',
    },
    message: `${req.user.name}, you have read access to this repository.`,
  });
});

/**
 * POST /repo/push - Push code to the repository
 * Requires: repo:write (collaborator and above)
 */
app.post('/repo/push', authenticate, checkPermission('repo:write'), (req, res) => {
  const { branch, message } = req.body || {};
  res.json({
    message: `${req.user.name} pushed code successfully.`,
    details: {
      branch: branch || 'main',
      commitMessage: message || 'Update files',
      pushedBy: req.user.name,
      role: req.user.role,
    },
  });
});

/**
 * DELETE /repo - Delete the repository
 * Requires: repo:delete (admin and owner only)
 */
app.delete('/repo', authenticate, checkPermission('repo:delete'), (req, res) => {
  res.json({
    message: `Repository deletion initiated by ${req.user.name}.`,
    warning: 'This action is irreversible!',
    deletedBy: req.user.name,
    role: req.user.role,
  });
});

/**
 * GET /repo/settings - View/modify repository settings
 * Requires: repo:settings (admin and owner only)
 */
app.get('/repo/settings', authenticate, checkPermission('repo:settings'), (req, res) => {
  res.json({
    settings: {
      visibility: 'public',
      allowForking: true,
      allowMergeCommit: true,
      allowSquashMerge: true,
      allowRebaseMerge: false,
      defaultBranch: 'main',
      branchProtection: {
        main: {
          requirePullRequest: true,
          requiredReviewers: 2,
          requireStatusChecks: true,
        },
      },
    },
    accessedBy: req.user.name,
  });
});

// --- Issue Routes ---

/**
 * GET /issues - List all issues
 * Requires: issues:read (all roles)
 */
app.get('/issues', authenticate, checkPermission('issues:read'), (req, res) => {
  res.json({
    issues: [
      { id: 1, title: 'Fix login bug', status: 'open', assignee: 'David Kim', labels: ['bug'] },
      { id: 2, title: 'Add dark mode', status: 'open', assignee: null, labels: ['enhancement'] },
      { id: 3, title: 'Update docs', status: 'closed', assignee: 'Carol Williams', labels: ['docs'] },
    ],
    viewedBy: req.user.name,
  });
});

/**
 * POST /issues - Create a new issue
 * Requires: issues:write (triager and above)
 */
app.post('/issues', authenticate, checkPermission('issues:write'), (req, res) => {
  const { title, body } = req.body || {};
  res.json({
    message: 'Issue created successfully.',
    issue: {
      id: 4,
      title: title || 'New issue',
      body: body || '',
      status: 'open',
      createdBy: req.user.name,
    },
  });
});

/**
 * PATCH /issues/:id/close - Close an issue
 * Requires: issues:close (triager and above)
 */
app.patch('/issues/:id/close', authenticate, checkPermission('issues:close'), (req, res) => {
  res.json({
    message: `Issue #${req.params.id} closed by ${req.user.name}.`,
    issue: { id: parseInt(req.params.id), status: 'closed', closedBy: req.user.name },
  });
});

/**
 * POST /issues/:id/assign - Assign an issue to a user
 * Requires: issues:assign (triager and above)
 */
app.post('/issues/:id/assign', authenticate, checkPermission('issues:assign'), (req, res) => {
  const { assignee } = req.body || {};
  res.json({
    message: `Issue #${req.params.id} assigned to ${assignee || 'someone'} by ${req.user.name}.`,
  });
});

// --- Pull Request Routes ---

/**
 * GET /pulls - List all pull requests
 * Requires: pr:read (all roles)
 */
app.get('/pulls', authenticate, checkPermission('pr:read'), (req, res) => {
  res.json({
    pullRequests: [
      { id: 10, title: 'Fix: resolve login timeout', status: 'open', author: 'David Kim', reviewers: ['Carol Williams'] },
      { id: 11, title: 'Feature: dark mode support', status: 'review', author: 'Carol Williams', reviewers: ['Bob Martinez'] },
    ],
    viewedBy: req.user.name,
  });
});

/**
 * POST /pulls - Create a new pull request
 * Requires: pr:write (collaborator and above)
 */
app.post('/pulls', authenticate, checkPermission('pr:write'), (req, res) => {
  const { title, base, head } = req.body || {};
  res.json({
    message: 'Pull request created successfully.',
    pullRequest: {
      id: 12,
      title: title || 'New pull request',
      base: base || 'main',
      head: head || 'feature-branch',
      createdBy: req.user.name,
      status: 'open',
    },
  });
});

/**
 * POST /pulls/:id/review - Review a pull request
 * Requires: pr:review (collaborator and above)
 */
app.post('/pulls/:id/review', authenticate, checkPermission('pr:review'), (req, res) => {
  const { action } = req.body || {};
  res.json({
    message: `PR #${req.params.id} reviewed by ${req.user.name}.`,
    review: {
      prId: parseInt(req.params.id),
      action: action || 'approved',
      reviewer: req.user.name,
    },
  });
});

/**
 * POST /pulls/:id/merge - Merge a pull request
 * Requires: pr:merge (maintainer and above)
 */
app.post('/pulls/:id/merge', authenticate, checkPermission('pr:merge'), (req, res) => {
  res.json({
    message: `PR #${req.params.id} merged by ${req.user.name}.`,
    merge: {
      prId: parseInt(req.params.id),
      mergedBy: req.user.name,
      strategy: 'squash',
    },
  });
});

// --- Member Management Routes ---

/**
 * GET /members - List repository members
 * Requires: members:read (all roles)
 */
app.get('/members', authenticate, checkPermission('members:read'), (req, res) => {
  res.json({
    members: Object.values(users).map(u => ({
      id: u.id,
      name: u.name,
      role: u.role,
      roleDescription: ROLES[u.role].description,
    })),
    viewedBy: req.user.name,
  });
});

/**
 * POST /members/invite - Invite a new member
 * Requires: members:invite (maintainer and above)
 */
app.post('/members/invite', authenticate, checkPermission('members:invite'), (req, res) => {
  const { email, role } = req.body || {};

  if (role && !ROLES[role]) {
    return res.status(400).json({
      error: 'Invalid role',
      availableRoles: Object.keys(ROLES),
    });
  }

  res.json({
    message: `Invitation sent to ${email || 'user@example.com'} as "${role || 'viewer'}".`,
    invitedBy: req.user.name,
  });
});

/**
 * DELETE /members/:id - Remove a member
 * Requires: members:remove (admin and owner only)
 */
app.delete('/members/:id', authenticate, checkPermission('members:remove'), (req, res) => {
  const targetUser = users[req.params.id];

  if (!targetUser) {
    return res.status(404).json({ error: 'User not found' });
  }

  // Prevent removing an owner (business logic)
  if (targetUser.role === 'owner') {
    return res.status(403).json({
      error: 'Cannot remove the repository owner.',
    });
  }

  res.json({
    message: `${targetUser.name} removed from the repository by ${req.user.name}.`,
  });
});

/**
 * PATCH /members/:id/role - Change a member's role
 * Requires: members:change_role (admin and owner only)
 */
app.patch('/members/:id/role', authenticate, checkPermission('members:change_role'), (req, res) => {
  const { newRole } = req.body || {};
  const targetUser = users[req.params.id];

  if (!targetUser) {
    return res.status(404).json({ error: 'User not found' });
  }

  if (!newRole || !ROLES[newRole]) {
    return res.status(400).json({
      error: 'Invalid or missing newRole',
      availableRoles: Object.keys(ROLES),
    });
  }

  // Prevent changing the owner's role (business logic)
  if (targetUser.role === 'owner' && req.user.role !== 'owner') {
    return res.status(403).json({
      error: 'Only the owner can change the owner\'s role.',
    });
  }

  const oldRole = targetUser.role;
  targetUser.role = newRole;

  console.log(`[RBAC] Role changed: ${targetUser.name} from "${oldRole}" to "${newRole}" by ${req.user.name}`);

  res.json({
    message: `${targetUser.name}'s role changed from "${oldRole}" to "${newRole}".`,
    changedBy: req.user.name,
  });
});

// --- Admin Routes ---

/**
 * GET /admin/audit-log - View the audit log
 * Requires: admin:audit_log (admin and owner only)
 */
app.get('/admin/audit-log', authenticate, checkPermission('admin:audit_log'), (req, res) => {
  res.json({
    auditLog: [
      { timestamp: '2025-01-15T10:30:00Z', action: 'repo.settings.update', actor: 'Alice Chen', details: 'Changed default branch to main' },
      { timestamp: '2025-01-14T14:20:00Z', action: 'member.invited', actor: 'Bob Martinez', details: 'Invited frank@example.com as viewer' },
      { timestamp: '2025-01-13T09:15:00Z', action: 'pr.merged', actor: 'Carol Williams', details: 'Merged PR #8: Add CI pipeline' },
      { timestamp: '2025-01-12T16:45:00Z', action: 'member.role_changed', actor: 'Alice Chen', details: 'Changed David Kim from viewer to collaborator' },
    ],
    viewedBy: req.user.name,
  });
});

/**
 * GET /admin/billing - View billing information
 * Requires: admin:billing (owner only)
 */
app.get('/admin/billing', authenticate, checkPermission('admin:billing'), (req, res) => {
  res.json({
    billing: {
      plan: 'Team',
      seats: 6,
      monthlyCost: '$25.00',
      nextBillingDate: '2025-02-15',
      paymentMethod: '**** **** **** 1234',
    },
    viewedBy: req.user.name,
  });
});

// =============================================================================
// SECTION 6: Error Handling
// =============================================================================

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Route ${req.method} ${req.path} does not exist.`,
    hint: 'Visit GET / for available endpoints.',
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({
    error: 'Internal Server Error',
    message: err.message,
  });
});

// =============================================================================
// SECTION 7: Start Server
// =============================================================================

app.listen(PORT, () => {
  console.log('============================================================');
  console.log('  RBAC (Role-Based Access Control) Demo Server');
  console.log(`  Running on http://localhost:${PORT}`);
  console.log('============================================================');
  console.log('');
  console.log('Role Hierarchy (most to least privileged):');
  console.log('  owner > admin > maintainer > collaborator > triager > viewer');
  console.log('');
  console.log('Test Users:');
  for (const user of Object.values(users)) {
    const permCount = RESOLVED_PERMISSIONS[user.role].length;
    console.log(`  ${user.id}: ${user.name} (${user.role}) - ${permCount} permissions`);
  }
  console.log('');
  console.log('Quick Start:');
  console.log('  1. POST /login with { "userId": "user1" } to get a token');
  console.log('  2. Use the token in the Authorization header');
  console.log('  3. Try different routes to see RBAC in action');
  console.log('');
  console.log('Example with curl:');
  console.log('  curl -X POST http://localhost:3008/login -H "Content-Type: application/json" -d \'{"userId":"user1"}\'');
  console.log('  curl http://localhost:3008/repo -H "Authorization: <token>"');
  console.log('============================================================');
});
