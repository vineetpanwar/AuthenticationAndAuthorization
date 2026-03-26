# RBAC: The Most Popular Authorization Model and How to Implement It

*Estimated read time: 12 minutes*

---

You've solved authentication. Your users are who they say they are. Now comes the harder question: **what are they allowed to do?**

Can Alice delete the production database? Can Bob view salary reports? Can the intern push to the main branch?

This is **authorization**, and the most widely adopted model for handling it is **Role-Based Access Control (RBAC)**. You're already using it, even if you don't realize it. Every time you assign someone as an "admin" or "viewer" or "editor," you're doing RBAC.

Let's understand it properly.

---

## What Is RBAC?

RBAC is a model where access decisions are based on **roles** assigned to users, not on the users themselves. Instead of granting permissions directly to individuals, you:

1. Define **roles** (admin, editor, viewer)
2. Assign **permissions** to roles (admin can delete, editor can write, viewer can read)
3. Assign **roles** to users (Alice is an admin, Bob is a viewer)

It's a layer of indirection that makes everything manageable.

```
┌────────────────────────────────────────────────────────────┐
│                  The RBAC Model                             │
│                                                             │
│  ┌───────┐     ┌──────────┐     ┌──────────────┐          │
│  │ Users │────►│  Roles   │────►│ Permissions  │          │
│  └───────┘     └──────────┘     └──────────────┘          │
│                                                             │
│  Alice ──────► Admin ──────────► create, read,             │
│                                   update, delete            │
│                                                             │
│  Bob ────────► Editor ─────────► create, read, update      │
│                                                             │
│  Charlie ────► Viewer ─────────► read                      │
│                                                             │
└────────────────────────────────────────────────────────────┘
```

### Why Not Assign Permissions Directly to Users?

Imagine you have 500 employees and 50 different permissions. Assigning permissions individually means managing 25,000 relationships. When a new permission is added, you might need to update hundreds of user records.

With RBAC, you manage a handful of roles. When a new permission is added, you update the role once, and every user with that role gets it automatically.

```
WITHOUT RBAC (Direct Assignment):
  Alice --> [read, write, delete, admin_panel, export, ...]
  Bob   --> [read, write, export, ...]
  Carol --> [read, write, delete, admin_panel, export, ...]
  Dave  --> [read, ...]
  ... (x500 users -- nightmare to maintain)

WITH RBAC:
  Admin  --> [read, write, delete, admin_panel, export]
  Editor --> [read, write, export]
  Viewer --> [read]

  Alice --> Admin
  Bob   --> Editor
  Carol --> Admin
  Dave  --> Viewer
  ... (easy to maintain, easy to audit)
```

---

## The RBAC Hierarchy

Many RBAC implementations support **role hierarchies**, where higher-level roles inherit permissions from lower-level ones.

```
┌─────────────────────────────────────────────────────┐
│              Role Hierarchy Example                   │
│                                                      │
│                   ┌───────────┐                      │
│                   │  Super    │                      │
│                   │  Admin    │                      │
│                   └─────┬─────┘                      │
│                         │ inherits                   │
│                   ┌─────▼─────┐                      │
│                   │  Admin    │                      │
│                   └─────┬─────┘                      │
│                         │ inherits                   │
│                   ┌─────▼─────┐                      │
│                   │  Editor   │                      │
│                   └─────┬─────┘                      │
│                         │ inherits                   │
│                   ┌─────▼─────┐                      │
│                   │  Viewer   │                      │
│                   └───────────┘                      │
│                                                      │
│  Viewer:      read                                   │
│  Editor:      read + write + comment                 │
│  Admin:       read + write + comment + delete +      │
│               manage_users                           │
│  Super Admin: read + write + comment + delete +      │
│               manage_users + system_config           │
└─────────────────────────────────────────────────────┘
```

An Admin automatically has all Editor permissions, which includes all Viewer permissions. You only define the *additional* permissions at each level.

---

## Real-World RBAC Examples

### GitHub

GitHub has one of the most visible RBAC implementations:

```
┌──────────────────────────────────────────────────────────┐
│              GitHub Repository Roles                      │
├───────────────┬──────────────────────────────────────────┤
│ Role          │ Permissions                              │
├───────────────┼──────────────────────────────────────────┤
│ Read          │ Clone, view code, open issues            │
│ Triage        │ + manage issues and PRs (no code write)  │
│ Write         │ + push code, merge PRs                   │
│ Maintain      │ + manage repo settings (no destructive)  │
│ Admin         │ + delete repo, manage access, everything │
└───────────────┴──────────────────────────────────────────┘
```

When you add a collaborator to a repo, you assign them a role, not individual permissions. Simple.

### Stripe

Stripe's dashboard uses RBAC for team access:

```
┌──────────────────────────────────────────────────────────┐
│              Stripe Dashboard Roles                       │
├───────────────┬──────────────────────────────────────────┤
│ Role          │ Can Do                                   │
├───────────────┼──────────────────────────────────────────┤
│ Administrator │ Everything: billing, API keys, team      │
│ Developer     │ API keys, webhooks, logs                 │
│ Analyst       │ View reports and analytics               │
│ Support       │ View and refund payments                 │
│ View only     │ Read-only access to dashboard            │
└───────────────┴──────────────────────────────────────────┘
```

### AWS IAM

AWS uses a sophisticated RBAC model where roles are assumed by users, services, or even other AWS accounts:

```
┌──────────────────────────────────────────────────────────┐
│                  AWS IAM Example                          │
│                                                           │
│  Role: "S3ReadOnlyRole"                                   │
│  ┌─────────────────────────────────────────┐             │
│  │ Policy:                                  │             │
│  │ {                                        │             │
│  │   "Effect": "Allow",                     │             │
│  │   "Action": [                            │             │
│  │     "s3:GetObject",                      │             │
│  │     "s3:ListBucket"                      │             │
│  │   ],                                     │             │
│  │   "Resource": "arn:aws:s3:::my-bucket/*" │             │
│  │ }                                        │             │
│  └─────────────────────────────────────────┘             │
│                                                           │
│  Assigned to: Developer Group (20 users)                  │
│  Result: All 20 devs can read from S3, nothing else      │
└──────────────────────────────────────────────────────────┘
```

---

## Implementing RBAC: The Database Model

Here's a clean relational model for RBAC:

```
┌──────────────────────────────────────────────────────────────┐
│                   RBAC Database Schema                        │
│                                                               │
│  ┌─────────┐       ┌──────────────┐       ┌──────────────┐  │
│  │  users   │       │ user_roles   │       │   roles      │  │
│  ├─────────┤       ├──────────────┤       ├──────────────┤  │
│  │ id      │──┐    │ user_id (FK) │    ┌──│ id           │  │
│  │ name    │  └───►│ role_id (FK) │◄───┘  │ name         │  │
│  │ email   │       └──────────────┘       │ description  │  │
│  └─────────┘                              └──────┬───────┘  │
│                                                   │          │
│                    ┌──────────────┐               │          │
│                    │role_perms    │               │          │
│  ┌─────────────┐  ├──────────────┤               │          │
│  │ permissions │  │ role_id (FK) │◄──────────────┘          │
│  ├─────────────┤  │ perm_id (FK) │                          │
│  │ id          │◄─│              │                          │
│  │ name        │  └──────────────┘                          │
│  │ description │                                            │
│  └─────────────┘                                            │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

And the authorization check in pseudocode:

```python
def can_user_do(user_id, permission_name):
    # Get all roles for the user
    roles = db.query(
        "SELECT role_id FROM user_roles WHERE user_id = ?",
        user_id
    )

    # Check if any role has the required permission
    for role in roles:
        has_perm = db.query(
            """SELECT 1 FROM role_permissions rp
               JOIN permissions p ON rp.perm_id = p.id
               WHERE rp.role_id = ? AND p.name = ?""",
            role.role_id, permission_name
        )
        if has_perm:
            return True

    return False
```

In practice, you'd cache this aggressively. Role-permission mappings rarely change, so they're perfect candidates for caching.

---

## Implementation Patterns

### Pattern 1: Middleware Check

The most common pattern in web applications -- check permissions in middleware before the request reaches the handler:

```python
@app.route("/admin/users", methods=["DELETE"])
@require_role("admin")
def delete_user(user_id):
    # Only admins reach this code
    ...
```

### Pattern 2: Permission-Based (More Granular)

Instead of checking roles directly, check permissions. This decouples your code from specific role names:

```python
@app.route("/posts", methods=["POST"])
@require_permission("posts:create")
def create_post():
    # Anyone with "posts:create" permission reaches this code
    # Could be an admin, editor, or any custom role
    ...
```

### Pattern 3: Embed Roles in JWT

For stateless architectures, embed the user's roles directly in the JWT:

```json
{
  "sub": "user_123",
  "roles": ["editor", "reviewer"],
  "permissions": ["posts:create", "posts:read", "posts:update", "reviews:create"]
}
```

Each microservice can then make authorization decisions without calling a central auth service. The trade-off: role changes don't take effect until the token is refreshed.

### Pattern 4: Policy-as-Code

Use a dedicated policy engine like **Open Policy Agent (OPA)** to externalize authorization logic:

```rego
# policy.rego
allow {
    input.method == "DELETE"
    input.path == "/api/posts"
    "admin" in input.user.roles
}

allow {
    input.method == "GET"
    input.path == "/api/posts"
    "viewer" in input.user.roles
}
```

This separates authorization logic from application code entirely.

---

## Common RBAC Pitfalls

### 1. Role Explosion
You start with 3 roles. Then marketing needs a special role. Then the finance team. Then a "read-only admin" for auditors. Before you know it, you have 47 roles and nobody knows what each one does.

**Fix:** Keep roles broad and use permission composition. A role is a *collection* of permissions, not a 1:1 mapping to a job title.

### 2. Checking Roles Instead of Permissions
Don't write `if user.role == "admin"` in your code. What happens when you create a "super_admin" role? You'd have to update every check.

**Fix:** Check permissions: `if user.has_permission("users:delete")`. Roles are an administrative concept; permissions are the enforcement mechanism.

### 3. No Separation of Duties
If one role can both approve and execute financial transactions, you have a compliance problem.

**Fix:** Design roles so that critical workflows require multiple roles to complete.

### 4. Forgetting the Default
What happens when a user has no role? They should have **zero access** by default. This is the principle of least privilege.

---

## RBAC Limitations

RBAC is powerful but not perfect. It struggles with:

- **Context-dependent access:** "Editors can edit, but only their own posts." RBAC doesn't naturally handle ownership.
- **Time-based access:** "Contractors can access the system only during business hours."
- **Environmental conditions:** "Access is allowed only from the corporate VPN."
- **Fine-grained resource-level control:** "Alice can edit Document A but not Document B."

When you hit these limitations, you need to look beyond RBAC to models like **ABAC** (Attribute-Based Access Control) and **ACL** (Access Control Lists).

---

## Key Takeaways

- **RBAC** assigns permissions to roles, then roles to users. It's a layer of indirection that simplifies access management.
- Use **role hierarchies** to reduce duplication. Higher roles inherit lower role permissions.
- In your code, check **permissions**, not roles. This keeps your authorization logic flexible.
- Watch out for **role explosion** -- keep roles broad and compose them from fine-grained permissions.
- RBAC works best for **static, organization-wide policies**. For dynamic, context-dependent rules, you'll need ABAC or ACL.
- **Default deny.** If a user has no role, they have no access.

---

## What's Next?

RBAC handles most authorization needs, but what about cases where access depends on attributes like location, time, or document ownership? That's where **ABAC** and **ACL** come in -- two complementary models that handle what RBAC can't.

**Next up:** [Beyond RBAC: Understanding ABAC and ACL for Fine-Grained Access Control](./08-abac-and-acl.md)
