/**
 * ============================================================================
 * ACCESS CONTROL LISTS (ACL) - Authorization Server
 * ============================================================================
 *
 * WHAT IS ACL?
 * Access Control Lists associate permissions directly with individual
 * resources. Each resource maintains a list of entries that specify which
 * users (or groups) have which permissions on that specific resource.
 * Think of it as a guest list on each resource's door.
 *
 * HOW IT WORKS:
 *   Resource --> ACL --> { user1: [read, write], user2: [read], group1: [read] }
 *
 * KEY CONCEPTS:
 *   - ACL Entry: A (subject, permission-set) pair attached to a resource
 *   - Subject: A user or group that the entry applies to
 *   - Permission Set: The specific actions allowed (read, write, delete, etc.)
 *   - Owner: The user who created the resource (usually has full control)
 *   - Inheritance: ACLs can sometimes be inherited from parent containers
 *   - Sharing: The act of adding an ACL entry for another user
 *
 * ACL vs RBAC vs ABAC:
 *   - RBAC: Permissions are on the USER (via roles). "What can this user do?"
 *   - ABAC: Permissions derived from ATTRIBUTES. "Do the attributes align?"
 *   - ACL:  Permissions are on the RESOURCE. "Who is allowed on this resource?"
 *
 * REAL-WORLD EXAMPLES:
 *   - Google Drive: Each file/folder has sharing settings (owner, editor, commenter, viewer)
 *   - Dropbox: Shared folders with per-user permission levels
 *   - Unix/Linux filesystem: rwx permissions per user/group/other
 *   - AWS S3 bucket policies: Per-object ACLs for read/write access
 *   - SharePoint: Document libraries with per-item permissions
 *   - Notion: Page-level sharing with specific users/groups
 *
 * PROS:
 *   - Intuitive - permissions are right on the resource
 *   - Fine-grained per-resource control
 *   - Users can manage sharing of their own resources
 *   - Great for collaborative systems (docs, files, projects)
 *
 * CONS:
 *   - Doesn't scale well: N users x M resources = potentially N*M entries
 *   - Hard to answer "what can user X access?" (need to scan all resources)
 *   - Permission management becomes complex with many resources
 *   - Can lead to inconsistent permissions across resources
 *
 * THIS DEMO:
 *   Implements a Google Drive-like document sharing system with owner,
 *   editor, commenter, and viewer permission levels, plus CRUD operations
 *   on ACLs (share, update, revoke access).
 *
 * Port: 3010
 * ============================================================================
 */

const express = require('express');
const app = express();
const PORT = 3010;

app.use(express.json());

// =============================================================================
// SECTION 1: Permission Levels (Google Drive-like)
// =============================================================================

/**
 * Permission levels ordered from most to least privileged.
 * Higher-level permissions include all lower-level permissions.
 *
 * Google Drive model:
 *   Owner    - Full control (share, delete, transfer ownership)
 *   Editor   - Read + Write + Comment
 *   Commenter - Read + Comment
 *   Viewer   - Read only
 */
const PERMISSION_LEVELS = {
  owner: {
    level: 4,
    description: 'Full control: read, write, comment, delete, share, transfer ownership',
    actions: ['read', 'write', 'comment', 'delete', 'share', 'manage_acl', 'transfer_ownership'],
  },
  editor: {
    level: 3,
    description: 'Can read, write, and comment on the resource',
    actions: ['read', 'write', 'comment'],
  },
  commenter: {
    level: 2,
    description: 'Can read and add comments, but not edit the resource',
    actions: ['read', 'comment'],
  },
  viewer: {
    level: 1,
    description: 'Read-only access to the resource',
    actions: ['read'],
  },
};

/**
 * Check if a permission level grants a specific action.
 */
function permissionAllowsAction(permissionLevel, action) {
  const perm = PERMISSION_LEVELS[permissionLevel];
  if (!perm) return false;
  return perm.actions.includes(action);
}

// =============================================================================
// SECTION 2: Seed Data - Users
// =============================================================================

const users = {
  user1: {
    id: 'user1',
    name: 'Alice Chen',
    email: 'alice@example.com',
    avatar: 'https://i.pravatar.cc/150?u=alice',
  },
  user2: {
    id: 'user2',
    name: 'Bob Martinez',
    email: 'bob@example.com',
    avatar: 'https://i.pravatar.cc/150?u=bob',
  },
  user3: {
    id: 'user3',
    name: 'Carol Williams',
    email: 'carol@example.com',
    avatar: 'https://i.pravatar.cc/150?u=carol',
  },
  user4: {
    id: 'user4',
    name: 'David Kim',
    email: 'david@example.com',
    avatar: 'https://i.pravatar.cc/150?u=david',
  },
  user5: {
    id: 'user5',
    name: 'Eve Johnson',
    email: 'eve@example.com',
    avatar: 'https://i.pravatar.cc/150?u=eve',
  },
};

// =============================================================================
// SECTION 3: Seed Data - Resources with ACLs
// =============================================================================

/**
 * Each resource has:
 *   - Standard resource properties (id, title, content, etc.)
 *   - An ACL: a map of userId -> permissionLevel
 *   - An owner field (the creator, always has 'owner' permission)
 *
 * The ACL is the core data structure of this authorization model.
 * Format: acl: { userId: 'permissionLevel', ... }
 */
const resources = {
  doc1: {
    id: 'doc1',
    title: 'Project Roadmap 2025',
    content: 'Q1: Launch v2.0, Q2: Mobile app, Q3: Enterprise features, Q4: International expansion',
    type: 'document',
    createdBy: 'user1',
    createdAt: '2025-01-01T10:00:00Z',
    updatedAt: '2025-01-15T14:30:00Z',
    // ACL: Alice is owner, Bob can edit, Carol can comment, David can view
    acl: {
      user1: 'owner',
      user2: 'editor',
      user3: 'commenter',
      user4: 'viewer',
    },
    comments: [
      { id: 'c1', userId: 'user3', text: 'Should we move mobile app to Q1?', createdAt: '2025-01-10T09:00:00Z' },
    ],
  },
  doc2: {
    id: 'doc2',
    title: 'API Design Specification',
    content: 'RESTful API design following OpenAPI 3.0 standards with versioned endpoints...',
    type: 'document',
    createdBy: 'user2',
    createdAt: '2025-01-05T08:00:00Z',
    updatedAt: '2025-01-12T11:20:00Z',
    // ACL: Bob is owner, Alice can edit
    acl: {
      user2: 'owner',
      user1: 'editor',
    },
    comments: [],
  },
  doc3: {
    id: 'doc3',
    title: 'Team Meeting Notes - Jan 15',
    content: 'Discussed sprint velocity, upcoming deadlines, and resource allocation...',
    type: 'document',
    createdBy: 'user3',
    createdAt: '2025-01-15T15:00:00Z',
    updatedAt: '2025-01-15T16:30:00Z',
    // ACL: Carol is owner, shared with everyone as viewer
    acl: {
      user3: 'owner',
      user1: 'viewer',
      user2: 'viewer',
      user4: 'viewer',
      user5: 'viewer',
    },
    comments: [],
  },
  folder1: {
    id: 'folder1',
    title: 'Engineering Shared',
    content: null,
    type: 'folder',
    createdBy: 'user1',
    createdAt: '2025-01-01T08:00:00Z',
    updatedAt: '2025-01-01T08:00:00Z',
    // ACL: Alice owns, Bob and David can edit
    acl: {
      user1: 'owner',
      user2: 'editor',
      user4: 'editor',
    },
    comments: [],
  },
  sheet1: {
    id: 'sheet1',
    title: 'Budget Tracker',
    content: 'Monthly budget allocations and tracking for all departments...',
    type: 'spreadsheet',
    createdBy: 'user5',
    createdAt: '2025-01-03T09:00:00Z',
    updatedAt: '2025-01-14T10:15:00Z',
    // ACL: Eve owns, no one else has access (private)
    acl: {
      user5: 'owner',
    },
    comments: [],
  },
};

// Session storage
const sessions = {};

// Audit log for ACL changes
const auditLog = [];

/**
 * Log an ACL change for auditing purposes.
 */
function logAclChange(action, resourceId, performedBy, details) {
  const entry = {
    timestamp: new Date().toISOString(),
    action,
    resourceId,
    performedBy,
    details,
  };
  auditLog.push(entry);
  console.log(`[AUDIT] ${action}: ${JSON.stringify(details)} on "${resourceId}" by "${performedBy}"`);
}

// =============================================================================
// SECTION 4: ACL Utility Functions
// =============================================================================

/**
 * Get a user's permission level on a specific resource.
 * Returns null if the user has no access.
 */
function getUserPermission(resourceId, userId) {
  const resource = resources[resourceId];
  if (!resource) return null;
  return resource.acl[userId] || null;
}

/**
 * Check if a user can perform a specific action on a resource.
 */
function canPerformAction(resourceId, userId, action) {
  const permLevel = getUserPermission(resourceId, userId);
  if (!permLevel) return false;
  return permissionAllowsAction(permLevel, action);
}

/**
 * Get all resources accessible to a user.
 * This is the expensive operation in ACL systems - we have to scan all resources.
 */
function getAccessibleResources(userId) {
  const accessible = [];
  for (const resource of Object.values(resources)) {
    const permLevel = resource.acl[userId];
    if (permLevel) {
      accessible.push({
        id: resource.id,
        title: resource.title,
        type: resource.type,
        yourPermission: permLevel,
        actions: PERMISSION_LEVELS[permLevel].actions,
      });
    }
  }
  return accessible;
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
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  req.user = session.user;
  console.log(`[AUTH] Authenticated: ${req.user.name}`);
  next();
}

/**
 * Middleware Factory: aclCheck
 * Checks if the authenticated user has permission to perform an action
 * on the resource identified by :resourceId in the route.
 *
 * Usage: app.get('/resources/:resourceId', authenticate, aclCheck('read'), handler)
 */
function aclCheck(action) {
  return (req, res, next) => {
    const resourceId = req.params.resourceId;

    if (!resourceId) {
      return res.status(400).json({ error: 'No resource ID provided' });
    }

    const resource = resources[resourceId];
    if (!resource) {
      return res.status(404).json({
        error: 'Resource not found',
        availableResources: Object.keys(resources),
      });
    }

    const userPermission = getUserPermission(resourceId, req.user.id);

    if (!userPermission) {
      console.log(
        `[ACL] DENIED: ${req.user.name} has NO ACCESS to "${resource.title}" ` +
        `(attempted: ${action})`
      );
      return res.status(403).json({
        error: 'Access denied',
        message: 'You do not have any access to this resource.',
        resource: { id: resource.id, title: resource.title },
        hint: 'Ask the resource owner to share it with you.',
      });
    }

    if (!permissionAllowsAction(userPermission, action)) {
      console.log(
        `[ACL] DENIED: ${req.user.name} (${userPermission}) cannot "${action}" on "${resource.title}" ` +
        `(allowed actions: ${PERMISSION_LEVELS[userPermission].actions.join(', ')})`
      );
      return res.status(403).json({
        error: 'Insufficient permissions',
        message: `Your "${userPermission}" access does not allow the "${action}" action.`,
        resource: { id: resource.id, title: resource.title },
        yourPermission: userPermission,
        allowedActions: PERMISSION_LEVELS[userPermission].actions,
        requiredAction: action,
      });
    }

    // Attach resource and permission info to the request
    req.resource = resource;
    req.userPermission = userPermission;

    console.log(
      `[ACL] ALLOWED: ${req.user.name} (${userPermission}) "${action}" on "${resource.title}"`
    );
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
 * GET / - API documentation
 */
app.get('/', (req, res) => {
  res.json({
    title: 'ACL (Access Control Lists) Demo Server',
    port: PORT,
    description: 'Google Drive-like document sharing system with per-resource ACLs',
    permissionLevels: Object.entries(PERMISSION_LEVELS).map(([name, perm]) => ({
      name,
      level: perm.level,
      description: perm.description,
      actions: perm.actions,
    })),
    endpoints: {
      public: {
        'POST /login': 'Log in with { "userId": "user1" }',
        'GET /permission-levels': 'View all permission levels and their actions',
      },
      protected_resources: {
        'GET /resources': 'List all resources you have access to',
        'GET /resources/:resourceId': 'Read a resource (requires "read" action)',
        'PUT /resources/:resourceId': 'Update a resource (requires "write" action)',
        'DELETE /resources/:resourceId': 'Delete a resource (requires "delete" action)',
        'POST /resources': 'Create a new resource (you become the owner)',
        'POST /resources/:resourceId/comments': 'Add a comment (requires "comment" action)',
      },
      acl_management: {
        'GET /resources/:resourceId/acl': 'View the ACL for a resource (requires "read")',
        'POST /resources/:resourceId/acl': 'Share: add a user to the ACL (requires "share")',
        'PATCH /resources/:resourceId/acl/:userId': 'Update a user\'s permission (requires "manage_acl")',
        'DELETE /resources/:resourceId/acl/:userId': 'Revoke access for a user (requires "manage_acl")',
        'POST /resources/:resourceId/transfer': 'Transfer ownership (requires "transfer_ownership")',
      },
      utility: {
        'GET /me': 'View your user info',
        'GET /me/shared-with-me': 'List all resources shared with you',
        'GET /audit-log': 'View ACL change audit log (any authenticated user)',
      },
    },
    testUsers: Object.values(users).map(u => ({ userId: u.id, name: u.name })),
    sampleResources: Object.values(resources).map(r => ({
      id: r.id,
      title: r.title,
      type: r.type,
      owner: users[r.createdBy] ? users[r.createdBy].name : r.createdBy,
      sharedWith: Object.keys(r.acl).filter(uid => r.acl[uid] !== 'owner').length + ' users',
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
      })),
    });
  }

  const user = users[userId];
  const token = `acl-token-${userId}-${Date.now()}`;
  sessions[token] = { user, createdAt: new Date().toISOString() };

  // Show what resources this user has access to
  const accessibleResources = getAccessibleResources(userId);

  console.log(`[LOGIN] ${user.name} logged in - has access to ${accessibleResources.length} resources`);

  res.json({
    message: `Welcome, ${user.name}!`,
    token,
    accessibleResources,
    usage: 'Include this token in the Authorization header.',
  });
});

/**
 * GET /permission-levels - View all permission levels
 */
app.get('/permission-levels', (req, res) => {
  res.json({
    description: 'Permission levels in descending order of privilege. Each level includes all actions of lower levels.',
    levels: Object.entries(PERMISSION_LEVELS)
      .sort((a, b) => b[1].level - a[1].level)
      .map(([name, perm]) => ({
        name,
        level: perm.level,
        description: perm.description,
        actions: perm.actions,
      })),
  });
});

// ---------------------
// Protected Routes - Resources
// ---------------------

/**
 * GET /me - View your user info
 */
app.get('/me', authenticate, (req, res) => {
  res.json({
    user: req.user,
    accessibleResources: getAccessibleResources(req.user.id),
  });
});

/**
 * GET /me/shared-with-me - List resources shared with you (not owned)
 */
app.get('/me/shared-with-me', authenticate, (req, res) => {
  const shared = [];
  for (const resource of Object.values(resources)) {
    const permLevel = resource.acl[req.user.id];
    if (permLevel && permLevel !== 'owner') {
      const ownerUser = users[resource.createdBy];
      shared.push({
        id: resource.id,
        title: resource.title,
        type: resource.type,
        sharedBy: ownerUser ? ownerUser.name : resource.createdBy,
        yourPermission: permLevel,
        actions: PERMISSION_LEVELS[permLevel].actions,
      });
    }
  }
  res.json({
    sharedWithYou: shared,
    total: shared.length,
  });
});

/**
 * GET /resources - List all resources accessible to the current user
 */
app.get('/resources', authenticate, (req, res) => {
  const accessible = getAccessibleResources(req.user.id);
  res.json({
    resources: accessible,
    total: accessible.length,
    note: 'Only resources you have access to are shown. Private resources of other users are hidden.',
  });
});

/**
 * POST /resources - Create a new resource (the creator becomes the owner)
 */
app.post('/resources', authenticate, (req, res) => {
  const { title, content, type } = req.body || {};

  if (!title) {
    return res.status(400).json({
      error: 'Title is required',
      example: { title: 'My Document', content: 'Document content...', type: 'document' },
    });
  }

  const id = `res-${Date.now()}`;
  const newResource = {
    id,
    title,
    content: content || '',
    type: type || 'document',
    createdBy: req.user.id,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    // The creator is automatically the owner
    acl: {
      [req.user.id]: 'owner',
    },
    comments: [],
  };

  resources[id] = newResource;

  logAclChange('resource_created', id, req.user.name, {
    title,
    owner: req.user.name,
  });

  console.log(`[RESOURCE] Created "${title}" by ${req.user.name} (id: ${id})`);

  res.status(201).json({
    message: `Resource "${title}" created successfully. You are the owner.`,
    resource: {
      id: newResource.id,
      title: newResource.title,
      type: newResource.type,
      createdBy: req.user.name,
    },
    acl: { [req.user.id]: 'owner' },
  });
});

/**
 * GET /resources/:resourceId - Read a resource
 * Requires 'read' action (all permission levels have this)
 */
app.get('/resources/:resourceId', authenticate, aclCheck('read'), (req, res) => {
  const resource = req.resource;
  const ownerUser = users[resource.createdBy];

  res.json({
    resource: {
      id: resource.id,
      title: resource.title,
      content: resource.content,
      type: resource.type,
      owner: ownerUser ? ownerUser.name : resource.createdBy,
      createdAt: resource.createdAt,
      updatedAt: resource.updatedAt,
      commentCount: resource.comments.length,
    },
    yourPermission: req.userPermission,
    yourActions: PERMISSION_LEVELS[req.userPermission].actions,
  });
});

/**
 * PUT /resources/:resourceId - Update a resource
 * Requires 'write' action (editor and owner)
 */
app.put('/resources/:resourceId', authenticate, aclCheck('write'), (req, res) => {
  const resource = req.resource;
  const { title, content } = req.body || {};

  if (title) resource.title = title;
  if (content) resource.content = content;
  resource.updatedAt = new Date().toISOString();

  console.log(`[RESOURCE] Updated "${resource.title}" by ${req.user.name}`);

  res.json({
    message: `Resource "${resource.title}" updated successfully.`,
    resource: {
      id: resource.id,
      title: resource.title,
      updatedAt: resource.updatedAt,
      updatedBy: req.user.name,
    },
  });
});

/**
 * DELETE /resources/:resourceId - Delete a resource
 * Requires 'delete' action (owner only)
 */
app.delete('/resources/:resourceId', authenticate, aclCheck('delete'), (req, res) => {
  const resource = req.resource;
  const title = resource.title;

  delete resources[resource.id];

  logAclChange('resource_deleted', resource.id, req.user.name, { title });

  console.log(`[RESOURCE] Deleted "${title}" by ${req.user.name}`);

  res.json({
    message: `Resource "${title}" has been permanently deleted.`,
    deletedBy: req.user.name,
  });
});

/**
 * POST /resources/:resourceId/comments - Add a comment
 * Requires 'comment' action (commenter, editor, and owner)
 */
app.post('/resources/:resourceId/comments', authenticate, aclCheck('comment'), (req, res) => {
  const resource = req.resource;
  const { text } = req.body || {};

  if (!text) {
    return res.status(400).json({ error: 'Comment text is required', example: { text: 'Your comment here' } });
  }

  const comment = {
    id: `c-${Date.now()}`,
    userId: req.user.id,
    userName: req.user.name,
    text,
    createdAt: new Date().toISOString(),
  };

  resource.comments.push(comment);

  console.log(`[COMMENT] ${req.user.name} commented on "${resource.title}"`);

  res.status(201).json({
    message: `Comment added to "${resource.title}".`,
    comment,
    totalComments: resource.comments.length,
  });
});

// ---------------------
// ACL Management Routes
// ---------------------

/**
 * GET /resources/:resourceId/acl - View the ACL for a resource
 * Requires 'read' action (any access level can see who else has access)
 */
app.get('/resources/:resourceId/acl', authenticate, aclCheck('read'), (req, res) => {
  const resource = req.resource;

  const aclEntries = Object.entries(resource.acl).map(([userId, permLevel]) => {
    const user = users[userId];
    return {
      userId,
      name: user ? user.name : 'Unknown User',
      email: user ? user.email : 'unknown',
      permission: permLevel,
      actions: PERMISSION_LEVELS[permLevel].actions,
    };
  });

  // Sort: owner first, then by permission level descending
  aclEntries.sort((a, b) => {
    const levelA = PERMISSION_LEVELS[a.permission]?.level || 0;
    const levelB = PERMISSION_LEVELS[b.permission]?.level || 0;
    return levelB - levelA;
  });

  res.json({
    resource: { id: resource.id, title: resource.title },
    acl: aclEntries,
    totalEntries: aclEntries.length,
    yourPermission: req.userPermission,
  });
});

/**
 * POST /resources/:resourceId/acl - Share a resource with another user
 * Requires 'share' action (owner only)
 *
 * Body: { "userId": "user3", "permission": "editor" }
 *
 * This is the "Share" button in Google Drive.
 */
app.post('/resources/:resourceId/acl', authenticate, aclCheck('share'), (req, res) => {
  const resource = req.resource;
  const { userId, permission } = req.body || {};

  // Validate input
  if (!userId) {
    return res.status(400).json({
      error: 'userId is required',
      example: { userId: 'user3', permission: 'editor' },
      availableUsers: Object.keys(users).map(id => ({ userId: id, name: users[id].name })),
    });
  }

  if (!users[userId]) {
    return res.status(400).json({
      error: 'User not found',
      availableUsers: Object.keys(users),
    });
  }

  if (!permission || !PERMISSION_LEVELS[permission]) {
    return res.status(400).json({
      error: 'Invalid permission level',
      validLevels: Object.keys(PERMISSION_LEVELS).filter(p => p !== 'owner'),
      note: 'You cannot grant "owner" permission. Use the transfer endpoint instead.',
    });
  }

  // Cannot grant owner permission via sharing
  if (permission === 'owner') {
    return res.status(400).json({
      error: 'Cannot grant owner permission via sharing.',
      message: 'Use POST /resources/:resourceId/transfer to transfer ownership.',
    });
  }

  // Check if user already has access
  const existingPermission = resource.acl[userId];
  if (existingPermission) {
    return res.status(409).json({
      error: 'User already has access to this resource.',
      existingPermission,
      message: 'Use PATCH /resources/:resourceId/acl/:userId to update their permission.',
    });
  }

  // Grant access
  resource.acl[userId] = permission;

  const targetUser = users[userId];
  logAclChange('access_granted', resource.id, req.user.name, {
    targetUser: targetUser.name,
    permission,
    resourceTitle: resource.title,
  });

  console.log(`[ACL] ${req.user.name} shared "${resource.title}" with ${targetUser.name} as ${permission}`);

  res.status(201).json({
    message: `"${resource.title}" shared with ${targetUser.name} as ${permission}.`,
    acl: {
      userId,
      name: targetUser.name,
      permission,
      actions: PERMISSION_LEVELS[permission].actions,
    },
  });
});

/**
 * PATCH /resources/:resourceId/acl/:userId - Update a user's permission
 * Requires 'manage_acl' action (owner only)
 *
 * Body: { "permission": "viewer" }
 */
app.patch('/resources/:resourceId/acl/:userId', authenticate, aclCheck('manage_acl'), (req, res) => {
  const resource = req.resource;
  const targetUserId = req.params.userId;
  const { permission: newPermission } = req.body || {};

  // Cannot change the owner's permission (use transfer instead)
  if (resource.acl[targetUserId] === 'owner') {
    return res.status(400).json({
      error: 'Cannot change the owner\'s permission.',
      message: 'Use POST /resources/:resourceId/transfer to transfer ownership.',
    });
  }

  // Check if the target user has access
  const currentPermission = resource.acl[targetUserId];
  if (!currentPermission) {
    return res.status(404).json({
      error: 'User does not have access to this resource.',
      message: 'Use POST /resources/:resourceId/acl to grant access first.',
    });
  }

  // Validate new permission
  if (!newPermission || !PERMISSION_LEVELS[newPermission]) {
    return res.status(400).json({
      error: 'Invalid permission level',
      validLevels: Object.keys(PERMISSION_LEVELS).filter(p => p !== 'owner'),
    });
  }

  if (newPermission === 'owner') {
    return res.status(400).json({
      error: 'Cannot set owner permission. Use transfer endpoint.',
    });
  }

  if (newPermission === currentPermission) {
    return res.status(400).json({
      error: 'New permission is the same as the current permission.',
      currentPermission,
    });
  }

  // Update the permission
  resource.acl[targetUserId] = newPermission;

  const targetUser = users[targetUserId];
  logAclChange('permission_updated', resource.id, req.user.name, {
    targetUser: targetUser ? targetUser.name : targetUserId,
    oldPermission: currentPermission,
    newPermission,
  });

  console.log(
    `[ACL] ${req.user.name} changed ${targetUser ? targetUser.name : targetUserId}'s ` +
    `permission on "${resource.title}" from ${currentPermission} to ${newPermission}`
  );

  res.json({
    message: `Permission updated for ${targetUser ? targetUser.name : targetUserId}.`,
    change: {
      userId: targetUserId,
      oldPermission: currentPermission,
      newPermission,
      newActions: PERMISSION_LEVELS[newPermission].actions,
    },
  });
});

/**
 * DELETE /resources/:resourceId/acl/:userId - Revoke a user's access
 * Requires 'manage_acl' action (owner only)
 *
 * This is the "Remove" button in Google Drive's sharing settings.
 */
app.delete('/resources/:resourceId/acl/:userId', authenticate, aclCheck('manage_acl'), (req, res) => {
  const resource = req.resource;
  const targetUserId = req.params.userId;

  // Cannot remove the owner
  if (resource.acl[targetUserId] === 'owner') {
    return res.status(400).json({
      error: 'Cannot remove the owner from the ACL.',
      message: 'Transfer ownership first, then the previous owner can be removed.',
    });
  }

  // Cannot remove yourself (prevents accidental lockout)
  if (targetUserId === req.user.id) {
    return res.status(400).json({
      error: 'You cannot revoke your own access.',
    });
  }

  // Check if the user has access
  const currentPermission = resource.acl[targetUserId];
  if (!currentPermission) {
    return res.status(404).json({
      error: 'User does not have access to this resource.',
    });
  }

  // Revoke access
  delete resource.acl[targetUserId];

  const targetUser = users[targetUserId];
  logAclChange('access_revoked', resource.id, req.user.name, {
    targetUser: targetUser ? targetUser.name : targetUserId,
    previousPermission: currentPermission,
  });

  console.log(
    `[ACL] ${req.user.name} revoked ${targetUser ? targetUser.name : targetUserId}'s ` +
    `access to "${resource.title}" (was: ${currentPermission})`
  );

  res.json({
    message: `Access revoked for ${targetUser ? targetUser.name : targetUserId}.`,
    revoked: {
      userId: targetUserId,
      previousPermission: currentPermission,
    },
  });
});

/**
 * POST /resources/:resourceId/transfer - Transfer ownership
 * Requires 'transfer_ownership' action (owner only)
 *
 * Body: { "newOwnerId": "user2" }
 *
 * The current owner becomes an editor, and the target user becomes the owner.
 */
app.post('/resources/:resourceId/transfer', authenticate, aclCheck('transfer_ownership'), (req, res) => {
  const resource = req.resource;
  const { newOwnerId } = req.body || {};

  if (!newOwnerId) {
    return res.status(400).json({
      error: 'newOwnerId is required',
      example: { newOwnerId: 'user2' },
      availableUsers: Object.keys(users).map(id => ({ userId: id, name: users[id].name })),
    });
  }

  if (!users[newOwnerId]) {
    return res.status(400).json({ error: 'User not found', availableUsers: Object.keys(users) });
  }

  if (newOwnerId === req.user.id) {
    return res.status(400).json({ error: 'You are already the owner.' });
  }

  // Transfer ownership
  const previousOwner = req.user.id;
  resource.acl[previousOwner] = 'editor';  // Demote current owner to editor
  resource.acl[newOwnerId] = 'owner';       // Promote new owner
  resource.createdBy = newOwnerId;           // Update the createdBy field

  const newOwnerUser = users[newOwnerId];
  logAclChange('ownership_transferred', resource.id, req.user.name, {
    previousOwner: req.user.name,
    newOwner: newOwnerUser.name,
  });

  console.log(
    `[ACL] Ownership of "${resource.title}" transferred from ${req.user.name} to ${newOwnerUser.name}`
  );

  res.json({
    message: `Ownership of "${resource.title}" transferred to ${newOwnerUser.name}.`,
    transfer: {
      previousOwner: { userId: previousOwner, name: req.user.name, newPermission: 'editor' },
      newOwner: { userId: newOwnerId, name: newOwnerUser.name, permission: 'owner' },
    },
  });
});

// ---------------------
// Utility Routes
// ---------------------

/**
 * GET /audit-log - View ACL change audit log
 */
app.get('/audit-log', authenticate, (req, res) => {
  res.json({
    auditLog: auditLog.slice(-50), // Last 50 entries
    total: auditLog.length,
    note: 'Showing the most recent 50 entries.',
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
  console.log('  ACL (Access Control Lists) Demo Server');
  console.log(`  Running on http://localhost:${PORT}`);
  console.log('============================================================');
  console.log('');
  console.log('Permission Levels (highest to lowest):');
  for (const [name, perm] of Object.entries(PERMISSION_LEVELS).sort((a, b) => b[1].level - a[1].level)) {
    console.log(`  ${name.padEnd(10)} (level ${perm.level}): ${perm.actions.join(', ')}`);
  }
  console.log('');
  console.log('Test Users:');
  for (const user of Object.values(users)) {
    const resourceCount = getAccessibleResources(user.id).length;
    console.log(`  ${user.id}: ${user.name} - has access to ${resourceCount} resources`);
  }
  console.log('');
  console.log('Resources and their ACLs:');
  for (const resource of Object.values(resources)) {
    const aclSummary = Object.entries(resource.acl)
      .map(([uid, perm]) => `${users[uid] ? users[uid].name : uid}:${perm}`)
      .join(', ');
    console.log(`  ${resource.id}: "${resource.title}" (${resource.type})`);
    console.log(`    ACL: ${aclSummary}`);
  }
  console.log('');
  console.log('Quick Start:');
  console.log('  1. POST /login with { "userId": "user1" } (Alice - owns doc1, folder1)');
  console.log('  2. GET /resources to see what you can access');
  console.log('  3. GET /resources/doc1/acl to see who has access to doc1');
  console.log('  4. POST /resources/doc1/acl with { "userId": "user5", "permission": "editor" } to share');
  console.log('  5. Log in as user5 and try accessing doc1');
  console.log('');
  console.log('Try this scenario:');
  console.log('  - Login as user5 (Eve) -> GET /resources (only sees sheet1)');
  console.log('  - Login as user1 (Alice) -> share doc1 with user5');
  console.log('  - Login as user5 again -> GET /resources (now sees doc1 too!)');
  console.log('============================================================');
});
