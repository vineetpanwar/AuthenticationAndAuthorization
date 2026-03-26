# Role-Based Access Control (RBAC)

## Introduction

Role-Based Access Control (RBAC) is one of the most widely adopted authorization models in
modern software systems. At its core, RBAC restricts system access based on the **roles**
assigned to individual users within an organization. Instead of granting permissions directly
to each user, permissions are grouped into roles, and users are assigned one or more roles.

The fundamental insight behind RBAC is simple: in most organizations, access requirements
are determined by job function, not by individual identity. A "billing administrator" needs
the same permissions regardless of whether that person is Alice or Bob. By abstracting
permissions into roles, RBAC dramatically simplifies access management at scale.

RBAC was formalized in 1992 by David Ferraiolo and Rick Kuhn at NIST, and later standardized
as ANSI/INCITS 359-2004. Today it is the backbone of authorization in platforms ranging from
GitHub to AWS IAM to Kubernetes.

---

## How It Works (Step by Step)

1. **Define Permissions** -- Identify every atomic action the system supports
   (e.g., `read:article`, `delete:user`, `create:invoice`).

2. **Create Roles** -- Group permissions into named roles that correspond to job functions
   (e.g., `admin`, `editor`, `viewer`).

3. **Assign Users to Roles** -- When a user joins the system or changes responsibilities,
   assign them the appropriate role(s).

4. **Enforce at Access Time** -- When a user attempts an action, the system looks up the
   user's role(s), resolves the associated permissions, and grants or denies the request.

5. **Audit and Review** -- Periodically review role assignments and permission sets to
   ensure they still match organizational needs (principle of least privilege).

---

## The RBAC Model (ASCII Diagram)

```
  USERS                    ROLES                   PERMISSIONS              RESOURCES
 +-------+           +----------------+        +------------------+      +------------+
 | Alice |---+       |    Admin       |------->| create:project   |----->| Projects   |
 +-------+   \      +----------------+    +--->| delete:project   |      +------------+
              +----->|                |----+    | manage:users     |----->| Users DB   |
 +-------+   /      +----------------+         +------------------+      +------------+
 | Bob   |---+
 +-------+          +----------------+         +------------------+      +------------+
              +---->|    Editor      |-------->| create:article   |----->| Articles   |
 +-------+  /      +----------------+    +--->| edit:article      |      +------------+
 | Carol |--+                            |    | publish:article   |
 +-------+  \      +----------------+   |    +------------------+
             +---->|    Viewer      |---+
 +-------+  /     +----------------+         +------------------+      +------------+
 | Dave  |-+                        +------->| read:article     |----->| Articles   |
 +-------+                                   | read:dashboard   |----->| Dashboard  |
                                              +------------------+      +------------+

 Session:
 +-----------------------------------------------+
 | User: Carol                                    |
 | Active Roles: [Editor, Viewer]                 |
 | Effective Permissions:                         |
 |   create:article, edit:article,                |
 |   publish:article, read:article,               |
 |   read:dashboard                               |
 +-----------------------------------------------+
```

### Role Hierarchy (Advanced RBAC)

Many RBAC implementations support **role inheritance**, where senior roles automatically
inherit all permissions of junior roles.

```
              +-------------------+
              |   Super Admin     |   (inherits everything below)
              +---------+---------+
                        |
              +---------v---------+
              |      Admin        |   (inherits Editor + Viewer)
              +---------+---------+
                        |
              +---------v---------+
              |      Editor       |   (inherits Viewer)
              +---------+---------+
                        |
              +---------v---------+
              |      Viewer       |   (base role)
              +-------------------+
```

---

## RBAC Levels (NIST Model)

| Level   | Name            | Description                                                   |
|---------|-----------------|---------------------------------------------------------------|
| RBAC0   | Flat RBAC       | Users, roles, permissions. No hierarchy, no constraints.      |
| RBAC1   | Hierarchical    | Adds role inheritance (senior roles inherit junior roles).    |
| RBAC2   | Constrained     | Adds separation-of-duty constraints (static and dynamic).    |
| RBAC3   | Symmetric       | Combines RBAC1 + RBAC2 (hierarchy + constraints).            |

---

## Real-World Examples

### GitHub

GitHub is a textbook example of RBAC in action. Every repository has a set of predefined roles:

| Role          | Key Permissions                                                    |
|---------------|--------------------------------------------------------------------|
| **Owner**     | Full admin access -- delete repo, manage billing, transfer repo.   |
| **Admin**     | Manage settings, branch protections, webhooks.                     |
| **Maintainer**| Merge pull requests, manage issues, but cannot change settings.    |
| **Write**     | Push to branches, create PRs, manage issues.                      |
| **Triage**    | Manage issues and PRs without write access to code.                |
| **Read**      | Clone and pull. View issues and PRs.                               |

GitHub Organizations add **custom roles** (Enterprise plan) so that teams can define
bespoke permission bundles beyond the defaults.

### Stripe

Stripe's Dashboard uses RBAC to control which team members can do what:

- **Administrator** -- Full access to all dashboard features and API keys.
- **Developer** -- Access to API keys, webhooks, and logs. No billing access.
- **Analyst** -- Read-only access to reports and data exports.
- **Support Specialist** -- Can issue refunds and view customer data, but cannot access API keys.

This maps perfectly to RBAC: each role is a named bundle of permissions aligned to a job function.

### AWS IAM

AWS IAM allows you to create **IAM Roles** that can be assumed by users, services, or even
cross-account principals. Policies (JSON documents listing allowed actions on resources) are
attached to roles, and users/services assume those roles to gain access.

### Kubernetes

Kubernetes uses RBAC to control access to cluster resources. `Role` and `ClusterRole` objects
define permission sets, and `RoleBinding`/`ClusterRoleBinding` objects attach them to users
or service accounts.

---

## Pros and Cons

### Advantages

- **Simplicity** -- Easy to understand and explain. "Alice is an Editor" is intuitive.
- **Scalability** -- Adding a new user means assigning a role, not enumerating permissions.
- **Auditability** -- Easy to answer "who has access to what?" by inspecting role assignments.
- **Compliance** -- RBAC aligns well with SOC2, HIPAA, and PCI-DSS requirements for access control.
- **Least Privilege** -- Encourages granting only the permissions a job function requires.
- **Separation of Duties** -- RBAC2/RBAC3 constraints can enforce that no single user holds
  conflicting roles (e.g., "requester" and "approver").

### Disadvantages

- **Role Explosion** -- In complex organizations, the number of roles can grow uncontrollably.
  If Marketing-East needs different access than Marketing-West, you need separate roles.
- **Coarse-Grained** -- RBAC alone cannot express conditions like "allow access only during
  business hours" or "allow access only to documents you created."
- **Static** -- Role assignments do not adapt to context (location, time, device, risk score).
- **Maintenance Overhead** -- Roles must be regularly reviewed and pruned. Stale roles with
  excessive permissions are a common audit finding.
- **Not Resource-Specific** -- Pure RBAC says "Editors can edit articles" but not "Carol can
  edit *only her own* articles." That requires ABAC or ACL augmentation.

---

## When to Use RBAC

**Use RBAC when:**

- Your organization has clearly defined job functions with distinct access needs.
- You need a straightforward, auditable access model for compliance.
- The number of distinct access patterns is manageable (tens of roles, not thousands).
- You want to onboard and offboard users quickly by assigning/revoking roles.
- You are building B2B SaaS where tenants expect role-based team management.

**Avoid pure RBAC when:**

- Access decisions depend on resource attributes (ownership, classification, geography).
- You need fine-grained, per-object permissions (prefer ACLs or ABAC).
- Environmental context matters (time of day, IP address, device trust level).
- The domain is so complex that role explosion becomes inevitable.

---

## Implementation Considerations

### Database Schema (Relational)

```
users              roles              permissions          role_permissions       user_roles
+----+------+      +----+---------+   +----+-------------+ +--------+-------+   +--------+-------+
| id | name |      | id | name    |   | id | key         | | role_id| perm_id|  | user_id| role_id|
+----+------+      +----+---------+   +----+-------------+ +--------+-------+   +--------+-------+
| 1  | Alice|      | 1  | admin   |   | 1  | read:article| | 1      | 1     |   | 1      | 1     |
| 2  | Bob  |      | 2  | editor  |   | 2  | edit:article| | 1      | 2     |   | 2      | 2     |
| 3  | Carol|      | 3  | viewer  |   | 3  | delete:user | | 1      | 3     |   | 3      | 2     |
+----+------+      +----+---------+   +----+-------------+ | 2      | 1     |   | 3      | 3     |
                                                            | 2      | 2     |   +--------+-------+
                                                            | 3      | 1     |
                                                            +--------+-------+
```

### Middleware Pattern (Pseudocode)

```python
def require_permission(permission):
    def decorator(handler):
        def wrapper(request):
            user = get_current_user(request)
            roles = get_roles_for_user(user.id)
            permissions = get_permissions_for_roles(roles)
            if permission not in permissions:
                raise ForbiddenError("Insufficient permissions")
            return handler(request)
        return wrapper
    return decorator

@require_permission("edit:article")
def update_article(request):
    # Only users with the "edit:article" permission reach here
    ...
```

### Caching Strategy

Permission lookups happen on every request. To avoid database round-trips:

1. **Cache role-permission mappings** -- These change infrequently. Store in Redis with a
   TTL of 5-15 minutes. Invalidate on role update.
2. **Embed roles in the JWT** -- Include the user's roles in the access token so the
   authorization check is a local operation (no network call). Tradeoff: role changes
   require token refresh.
3. **Use a policy engine** -- Tools like Open Policy Agent (OPA) or Casbin load policies
   into memory and evaluate them in microseconds.

### Separation of Duties

In sensitive systems (finance, healthcare), enforce constraints:

- **Static SoD** -- A user cannot be assigned both `payment_requester` and `payment_approver`.
- **Dynamic SoD** -- A user who holds both roles cannot activate them in the same session.

---

## Comparison with Other Models

| Dimension              | RBAC                | ABAC                 | ACL                 |
|------------------------|---------------------|----------------------|---------------------|
| Abstraction level      | Role (group of perms)| Policy (attribute rules)| Per-object entries |
| Granularity            | Coarse to medium    | Very fine            | Very fine           |
| Scalability (users)    | Excellent           | Excellent            | Moderate            |
| Scalability (resources)| Good                | Excellent            | Poor at scale       |
| Context-awareness      | No                  | Yes                  | No                  |
| Ease of auditing       | High                | Medium               | Low at scale        |
| Implementation effort  | Low                 | High                 | Medium              |
| Best for               | Team/org management | Complex policies     | File/object sharing |

---

## Key Takeaways

1. RBAC maps permissions to **roles**, and roles to **users** -- creating a clean abstraction layer.
2. It is the most common authorization model in enterprise and SaaS applications.
3. Role hierarchy and separation-of-duty constraints add power but also complexity.
4. RBAC works best when access patterns align with job functions.
5. For fine-grained or context-aware decisions, combine RBAC with ABAC or ACLs.

---

## Further Reading

- NIST RBAC Standard: https://csrc.nist.gov/projects/role-based-access-control
- Ferraiolo, D.F. & Kuhn, D.R. (1992). "Role-Based Access Controls."
- Sandhu, R. et al. (1996). "Role-Based Access Control Models." IEEE Computer.
- GitHub Roles Documentation: https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories
