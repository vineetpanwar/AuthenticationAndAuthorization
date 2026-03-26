# Beyond RBAC: Understanding ABAC and ACL for Fine-Grained Access Control

*Estimated read time: 15 minutes*

---

RBAC is great until it isn't.

You're building a document management system. With RBAC, you can say "editors can edit documents." But what about "editors can edit documents they created, during business hours, from the corporate network"? Or "this specific document is shared with Alice but not Bob"?

RBAC deals in broad strokes: roles and permissions. But the real world demands **fine-grained, context-aware access control**. That's where **ABAC** (Attribute-Based Access Control) and **ACL** (Access Control Lists) come in.

These aren't replacements for RBAC -- they're extensions. And understanding when to reach for each model is one of the most valuable skills in security architecture.

---

## Why RBAC Isn't Always Enough

Let's look at access rules that RBAC can't express cleanly:

```
┌──────────────────────────────────────────────────────────────┐
│          Rules That Break RBAC                                │
│                                                               │
│  1. "Users can only edit their OWN documents"                │
│     --> RBAC has no concept of resource ownership             │
│                                                               │
│  2. "Access is allowed only from IP 10.0.0.0/8"             │
│     --> RBAC doesn't consider environmental attributes       │
│                                                               │
│  3. "Document X is shared with Alice, Bob, and Carol"        │
│     --> RBAC assigns permissions to roles, not to specific   │
│         resources                                             │
│                                                               │
│  4. "Managers can approve expenses under $10,000"            │
│     --> RBAC can't evaluate resource attributes like amount  │
│                                                               │
│  5. "Contractors lose access after 90 days"                  │
│     --> RBAC doesn't handle time-based conditions            │
└──────────────────────────────────────────────────────────────┘
```

Each of these requires context that RBAC simply doesn't have. Let's look at two models that fill the gap.

---

## ABAC: Attribute-Based Access Control

ABAC makes access decisions based on **attributes** -- properties of the user, the resource, the action, and the environment. Instead of "is this user an admin?", ABAC asks "does this combination of attributes satisfy the policy?"

### The Four Attribute Categories

```
┌──────────────────────────────────────────────────────────────┐
│                  ABAC Attribute Categories                     │
│                                                               │
│  ┌────────────────────┐      ┌────────────────────┐         │
│  │ SUBJECT Attributes │      │ RESOURCE Attributes │         │
│  │ (Who?)             │      │ (What?)             │         │
│  ├────────────────────┤      ├────────────────────┤         │
│  │ user.role          │      │ doc.owner           │         │
│  │ user.department    │      │ doc.classification  │         │
│  │ user.clearance     │      │ doc.created_at      │         │
│  │ user.location      │      │ doc.sensitivity     │         │
│  └────────────────────┘      └────────────────────┘         │
│                                                               │
│  ┌────────────────────┐      ┌────────────────────┐         │
│  │ ACTION Attributes  │      │ ENVIRONMENT         │         │
│  │ (How?)             │      │ Attributes (Where?) │         │
│  ├────────────────────┤      ├────────────────────┤         │
│  │ action.type        │      │ env.time            │         │
│  │ action.method      │      │ env.ip_address      │         │
│  │ action.target      │      │ env.device_type     │         │
│  │                    │      │ env.network          │         │
│  └────────────────────┘      └────────────────────┘         │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### How ABAC Works

An ABAC system evaluates **policies** against attributes at decision time:

```
┌──────────┐     ┌──────────────┐     ┌───────────────┐
│ Request   │────►│ Policy       │────►│ Decision      │
│           │     │ Engine       │     │ ALLOW / DENY  │
│ Subject:  │     │              │     └───────────────┘
│  alice    │     │ Evaluates    │
│ Action:   │     │ policies     │
│  edit     │     │ against      │
│ Resource: │     │ attributes   │
│  doc_123  │     │              │
│ Env:      │     │              │
│  10am,    │     │              │
│  VPN      │     │              │
└──────────┘     └──────────────┘
```

### ABAC Policies in Practice

Here's what ABAC policies look like:

**Policy 1: "Users can edit documents they own"**
```
ALLOW
  IF   subject.id == resource.owner_id
  AND  action.type == "edit"
```

**Policy 2: "Managers can approve expenses under $10,000"**
```
ALLOW
  IF   subject.role == "manager"
  AND  action.type == "approve"
  AND  resource.type == "expense"
  AND  resource.amount < 10000
```

**Policy 3: "Confidential documents are accessible only from corporate network during business hours"**
```
ALLOW
  IF   resource.classification == "confidential"
  AND  environment.network == "corporate"
  AND  environment.time >= 09:00
  AND  environment.time <= 18:00
```

**Policy 4: "Doctors can view patient records in their department"**
```
ALLOW
  IF   subject.role == "doctor"
  AND  action.type == "read"
  AND  resource.type == "patient_record"
  AND  subject.department == resource.department
```

### AWS IAM: ABAC in the Real World

AWS IAM is one of the most prominent ABAC implementations. IAM policies evaluate attributes of the principal, action, resource, and conditions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*",
      "Condition": {
        "StringEquals": {
          "s3:ExistingObjectTag/department": "${aws:PrincipalTag/department}"
        },
        "IpAddress": {
          "aws:SourceIp": "10.0.0.0/8"
        }
      }
    }
  ]
}
```

This policy says: "Allow S3 object reads, but only when the object's department tag matches the user's department tag, and only from the 10.0.0.0/8 network."

That's ABAC in action. No fixed roles -- just attribute matching.

### The ABAC Decision Flow

```
┌──────────┐                                     ┌──────────┐
│ Client    │                                     │ Server    │
└─────┬────┘                                     └─────┬────┘
      │                                                 │
      │  Request: "Alice wants to edit doc_123"         │
      │────────────────────────────────────────────────►│
      │                                                 │
      │           ┌────────────────────────────────────┐│
      │           │ 1. Collect subject attributes      ││
      │           │    alice: role=editor, dept=eng     ││
      │           │                                    ││
      │           │ 2. Collect resource attributes     ││
      │           │    doc_123: owner=alice,            ││
      │           │    classification=internal          ││
      │           │                                    ││
      │           │ 3. Collect env attributes          ││
      │           │    time=14:30, ip=10.0.1.42        ││
      │           │                                    ││
      │           │ 4. Evaluate ALL applicable         ││
      │           │    policies                        ││
      │           │                                    ││
      │           │ 5. Result: ALLOW                   ││
      │           └────────────────────────────────────┘│
      │                                                 │
      │  200 OK                                         │
      │◄────────────────────────────────────────────────│
      │                                                 │
```

---

## ACL: Access Control Lists

While ABAC evaluates policies dynamically, ACLs take a different approach: they attach **permission lists directly to resources**. Each resource has a list that says exactly who can do what to it.

If RBAC is "what can this role do?" and ABAC is "do these attributes match the policy?", then ACL is "what does this resource's permission list say?"

### How ACLs Work

```
┌──────────────────────────────────────────────────────────────┐
│                   ACL Model                                   │
│                                                               │
│  Resource: "Q3 Financial Report.pdf"                         │
│  ┌──────────────────────────────────────────────────┐        │
│  │ Access Control List:                              │        │
│  │                                                    │        │
│  │  Alice       --> [read, write, share]             │        │
│  │  Bob         --> [read]                           │        │
│  │  Carol       --> [read, comment]                  │        │
│  │  Finance Team --> [read, write]                   │        │
│  │  Everyone    --> (no access)                      │        │
│  └──────────────────────────────────────────────────┘        │
│                                                               │
│  Resource: "Company Handbook.pdf"                            │
│  ┌──────────────────────────────────────────────────┐        │
│  │ Access Control List:                              │        │
│  │                                                    │        │
│  │  HR Team     --> [read, write]                    │        │
│  │  Everyone    --> [read]                           │        │
│  └──────────────────────────────────────────────────┘        │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### Google Drive: ACL in the Real World

Google Drive is a textbook ACL system. Every file and folder has its own access list:

```
┌──────────────────────────────────────────────────────┐
│  Google Drive - "Project Proposal.docx"              │
│                                                       │
│  Shared with:                                         │
│  ┌───────────────────────────────────────────┐       │
│  │ alice@company.com         Owner           │       │
│  │ bob@company.com           Can edit        │       │
│  │ carol@partner.com         Can comment     │       │
│  │ dave@client.com           Can view        │       │
│  │ engineering@company.com   Can edit        │       │
│  │ Anyone with link          Can view        │       │
│  └───────────────────────────────────────────┘       │
│                                                       │
│  This IS the ACL for this specific document.         │
└──────────────────────────────────────────────────────┘
```

When Bob tries to access the document, Google checks the ACL for that document. Is Bob on the list? What permission level does he have? That's it.

### ACL Data Model

```
┌──────────────────────────────────────────────────────────────┐
│                  ACL Database Schema                          │
│                                                               │
│  ┌─────────────┐       ┌───────────────────┐                │
│  │ resources    │       │ acl_entries       │                │
│  ├─────────────┤       ├───────────────────┤                │
│  │ id          │──┐    │ resource_id (FK)  │                │
│  │ name        │  └───►│ principal_id      │                │
│  │ type        │       │ principal_type    │                │
│  │ owner_id    │       │ (user/group/all)  │                │
│  └─────────────┘       │ permission        │                │
│                         │ (read/write/admin)│                │
│                         │ granted_by        │                │
│                         │ granted_at        │                │
│                         └───────────────────┘                │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

The authorization check:

```python
def can_access(user_id, resource_id, permission):
    # Check direct user entry
    entry = db.query(
        """SELECT 1 FROM acl_entries
           WHERE resource_id = ?
           AND principal_id = ?
           AND principal_type = 'user'
           AND permission >= ?""",
        resource_id, user_id, permission
    )
    if entry:
        return True

    # Check group entries
    user_groups = get_user_groups(user_id)
    for group in user_groups:
        entry = db.query(
            """SELECT 1 FROM acl_entries
               WHERE resource_id = ?
               AND principal_id = ?
               AND principal_type = 'group'
               AND permission >= ?""",
            resource_id, group.id, permission
        )
        if entry:
            return True

    return False
```

---

## The Comparison: RBAC vs ABAC vs ACL

```
┌──────────────────┬───────────────────┬───────────────────┬───────────────────┐
│                  │      RBAC         │      ABAC         │      ACL          │
├──────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Decision based   │ User's role       │ Multiple          │ Resource's        │
│ on               │                   │ attributes        │ permission list   │
├──────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Granularity      │ Coarse            │ Very fine         │ Per-resource      │
│                  │ (role-level)      │ (attribute-level) │ fine              │
├──────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Best for         │ Organization-wide │ Complex, dynamic  │ Resource-level    │
│                  │ policies          │ policies          │ sharing           │
├──────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Complexity       │ Low               │ High              │ Medium            │
├──────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Scalability      │ Excellent         │ Good (depends     │ Can be costly     │
│                  │                   │ on policy engine) │ at scale          │
├──────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Context-aware    │ No                │ Yes               │ No                │
├──────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Dynamic          │ No                │ Yes               │ No                │
│ conditions       │                   │ (time, location)  │                   │
├──────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Real-world       │ GitHub roles,     │ AWS IAM policies, │ Google Drive      │
│ examples         │ Stripe dashboard  │ XACML, OPA        │ sharing, file     │
│                  │                   │                   │ system perms      │
├──────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Audit trail      │ Easy              │ Moderate          │ Per-resource      │
├──────────────────┼───────────────────┼───────────────────┼───────────────────┤
│ Setup effort     │ Low               │ High              │ Medium            │
└──────────────────┴───────────────────┴───────────────────┴───────────────────┘
```

---

## When to Use Which

### Use RBAC When:
- Your access rules map cleanly to organizational roles
- You need simplicity and broad policies
- Most users with the same job title need the same access
- You're building internal tools, dashboards, or admin panels

### Use ABAC When:
- Access depends on multiple dynamic conditions
- You need rules like "only during business hours" or "only from this network"
- Different resources of the same type need different rules
- You're in healthcare, finance, or government (regulatory compliance)
- You want to avoid role explosion

### Use ACL When:
- Users need to share specific resources with specific people
- You're building a document/file system with per-item sharing
- Users themselves need to control who accesses their content
- The permission model is inherently per-resource (think Google Drive, Dropbox, Notion)

### Use a Combination (Most Common):

In practice, most systems use a **hybrid approach**:

```
┌──────────────────────────────────────────────────────────┐
│              Hybrid Authorization Example                  │
│                                                           │
│  Layer 1 - RBAC:                                          │
│    "Is this user an Editor? OK, they CAN edit."          │
│                                                           │
│  Layer 2 - ACL:                                           │
│    "Is this specific document shared with them?           │
│     OK, they have access to THIS document."              │
│                                                           │
│  Layer 3 - ABAC:                                          │
│    "Are they on the corporate network? Is it within       │
│     business hours? OK, conditions are met."             │
│                                                           │
│  ALL THREE must pass = ACCESS GRANTED                     │
└──────────────────────────────────────────────────────────┘
```

Google Workspace is a perfect example: RBAC for admin roles, ACLs for document sharing, and ABAC-like rules for context-aware access (device policies, location restrictions).

---

## Implementing Fine-Grained Access: Tools and Frameworks

If you're building a system that needs ABAC or ACL, consider these tools:

**Open Policy Agent (OPA):** A general-purpose policy engine that evaluates policies written in Rego. Great for ABAC.

**Casbin:** An authorization library that supports RBAC, ABAC, and ACL models. Available in Go, Java, Python, Node.js, and more.

**AWS Cedar:** Amazon's policy language for fine-grained permissions. Powers AWS Verified Permissions.

**Zanzibar/SpiceDB:** Google's relationship-based access control system (Zanzibar), with SpiceDB as an open-source implementation. Excellent for ACL at scale.

---

## Key Takeaways

- **RBAC** assigns permissions to roles. Simple and effective for organization-wide rules, but limited for context-dependent access.
- **ABAC** evaluates attributes of the subject, resource, action, and environment. Powerful for dynamic, condition-based policies.
- **ACL** attaches permission lists to individual resources. Ideal for user-driven sharing (like Google Drive).
- Most real-world systems use a **hybrid** of all three models.
- Choose based on your needs: RBAC for simplicity, ABAC for flexibility, ACL for per-resource control.
- Tools like **OPA**, **Casbin**, and **SpiceDB** can save you from building policy engines from scratch.

---

## What's Next?

We've now covered the full spectrum of authentication and authorization -- from Basic Auth all the way to fine-grained access control. In the final article, we'll put it all together into a comprehensive landscape view, helping you decide which approach to use for your specific situation.

**Next up:** [The Complete Authentication & Authorization Landscape: A Developer's Guide](./09-complete-auth-landscape.md)
