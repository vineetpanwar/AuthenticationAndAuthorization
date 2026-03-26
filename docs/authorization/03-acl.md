# Access Control Lists (ACL)

## Introduction

An Access Control List (ACL) is one of the oldest and most intuitive authorization models
in computing. At its core, an ACL is a list attached to a resource that specifies which
subjects (users, groups, or processes) are granted which permissions on that specific resource.

Think of it like a guest list at a venue. The venue (resource) has a list at the door, and
each entry on the list says who is allowed in and what they can do (e.g., "Alice -- full
access," "Bob -- read only," "Marketing Group -- read and comment").

ACLs have been foundational since the early days of operating systems. UNIX file permissions
(`rwxr-xr--`) are a simplified form of ACL. The POSIX.1e draft standard extended this to
full ACLs, and NTFS (Windows) has used rich ACLs since Windows NT. In the modern era, ACLs
power sharing in Google Drive, Dropbox, and countless file-sharing and collaboration platforms.

---

## How It Works (Step by Step)

1. **Resource Created** -- When a resource is created (file, document, database record),
   an ACL is initialized. Typically the creator is granted full control.

2. **Permissions Defined** -- The resource owner (or an administrator) adds entries to the
   ACL, specifying subjects and their permissions.

3. **Access Request** -- A user attempts to perform an action on the resource.

4. **ACL Lookup** -- The system retrieves the ACL for the target resource and searches for
   an entry matching the requesting user (directly or via group membership).

5. **Decision** -- If a matching entry grants the requested permission, access is allowed.
   If no entry matches or the entry explicitly denies the permission, access is denied.

6. **Propagation** -- For hierarchical resources (directories, folders), ACLs may be
   inherited by child resources, with optional overrides.

---

## The ACL Model (ASCII Diagram)

```
  RESOURCES AND THEIR ACCESS CONTROL LISTS

  +====================+     +=========================================+
  | Resource:          |     | Access Control List (ACL)               |
  | /docs/budget.xlsx  |     +=========================================+
  |                    |---->| Subject          | Permission            |
  +====================+     |-----------------+------------------------|
                             | Alice (owner)    | read, write, delete,  |
                             |                  | share, manage_acl     |
                             |-----------------|------------------------|
                             | Bob              | read, write           |
                             |-----------------|------------------------|
                             | @finance-team    | read                  |
                             |-----------------|------------------------|
                             | @everyone        | (no access)           |
                             |-----------------|------------------------|
                             | Carol            | DENY write            |
                             +---------------------------------------—--+

  ACCESS CHECK FLOW:

       +-------+                          +------------------+
       | Carol |--- wants to write ------>| /docs/budget.xlsx|
       +-------+                          +------------------+
                                                   |
                                           Look up ACL for Carol
                                                   |
                                                   v
                                    +-----------------------------+
                                    | Entry found: Carol -> DENY  |
                                    | write                       |
                                    +-----------------------------+
                                                   |
                                                   v
                                           ACCESS DENIED


  ACL INHERITANCE (Directory Tree):

       /projects/                ACL: [@eng-team: read,write]
           |
           +-- /projects/alpha/          Inherits parent ACL
           |       |                     + [Dave: manage_acl]
           |       +-- design.fig        Inherits from /projects/alpha/
           |       +-- spec.md           Inherits from /projects/alpha/
           |
           +-- /projects/beta/           Inherits parent ACL
                   |                     Override: [@eng-team: read ONLY]
                   +-- secret.doc        Inherits from /projects/beta/
```

### ACL Entry Structure

Each entry in an ACL (called an Access Control Entry, or ACE) typically contains:

```
+------------------------------------------------------------------+
| ACE (Access Control Entry)                                        |
+------------------------------------------------------------------+
| Subject Type  | Subject ID     | Permission Set  | Effect        |
|---------------|----------------|-----------------|---------------|
| user          | alice@corp.com | read,write,del  | ALLOW         |
| group         | @finance-team  | read            | ALLOW         |
| user          | carol@corp.com | write           | DENY          |
| special       | @everyone      | read            | ALLOW         |
+------------------------------------------------------------------+

 Priority Order (typical):
   1. Explicit DENY   (highest priority -- always wins)
   2. Explicit ALLOW
   3. Inherited DENY
   4. Inherited ALLOW
   5. Default DENY    (if no matching entry, deny)
```

---

## Real-World Examples

### Google Drive

Google Drive is perhaps the most visible consumer-facing ACL system. When you share a
document, you are editing its ACL:

| Entry              | Permission Level           |
|--------------------|----------------------------|
| alice@gmail.com    | Owner                      |
| bob@gmail.com      | Editor (can edit)           |
| carol@gmail.com    | Commenter (can comment)     |
| dave@gmail.com     | Viewer (can view)           |
| "Anyone with link" | Viewer                     |

The sharing dialog is literally a UI for managing ACL entries. Google Drive also supports:
- **Inheritance**: Files in a shared folder inherit the folder's ACL.
- **Override**: A file in a shared folder can restrict access beyond what the folder allows.
- **Expiration**: ACL entries can have an expiry date.
- **Transfer of Ownership**: The owner ACE can be reassigned.

### UNIX/Linux File Permissions

Traditional UNIX permissions are a simplified 3-entry ACL:

```
-rwxr-xr--  1 alice engineers  4096 Mar 15 10:00 deploy.sh
 |||  |||  |||
 |||  |||  +++-- Others:  read only
 |||  +++------- Group (engineers): read + execute
 +++------------ Owner (alice): read + write + execute
```

POSIX ACLs extend this with `setfacl`/`getfacl`:

```bash
$ getfacl deploy.sh
# file: deploy.sh
# owner: alice
# group: engineers
user::rwx
user:bob:r-x          # Specific user entry
group::r-x
group:devops:rwx       # Specific group entry
mask::rwx
other::r--
```

### Windows NTFS

NTFS ACLs are among the most sophisticated ACL implementations:

- Each file/folder has a **DACL** (Discretionary ACL) and an **SACL** (System ACL for auditing).
- ACEs support granular permissions: Read, Write, Execute, Delete, Change Permissions,
  Take Ownership, and many more.
- Inheritance flows from parent folders with fine-grained control over propagation.
- Explicit deny always overrides explicit allow.

### Amazon S3 Bucket ACLs

S3 supports both ACLs and bucket policies:

```xml
<AccessControlPolicy>
  <Owner>
    <ID>owner-id</ID>
  </Owner>
  <AccessControlList>
    <Grant>
      <Grantee xsi:type="CanonicalUser">
        <ID>user-id</ID>
      </Grantee>
      <Permission>FULL_CONTROL</Permission>
    </Grant>
    <Grant>
      <Grantee xsi:type="Group">
        <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI>
      </Grantee>
      <Permission>READ</Permission>
    </Grant>
  </AccessControlList>
</AccessControlPolicy>
```

Note: AWS now recommends bucket policies (ABAC-style) over ACLs for most use cases.

### Dropbox

Dropbox uses ACLs for shared folders and links, with permission levels:
- **Owner** -- Full control, can transfer ownership.
- **Editor** -- Can add, edit, and delete files.
- **Viewer** -- Can view and download but not modify.

---

## Pros and Cons

### Advantages

- **Intuitive** -- "Who has access to this file?" is answered directly by reading the ACL.
  Non-technical users understand sharing dialogs (which are ACL editors).
- **Fine-Grained** -- Permissions are set per resource, enabling precise control.
- **Flexible** -- Any subject can be granted any combination of permissions on any resource.
- **User-Empowering** -- Resource owners can manage their own ACLs without admin intervention.
- **Well-Understood** -- Decades of implementation experience in operating systems, databases,
  and cloud platforms.
- **Deny Entries** -- Explicit deny rules provide an important safety mechanism.

### Disadvantages

- **Scalability Problems** -- As the number of resources grows, managing individual ACLs
  becomes a nightmare. A system with 1 million documents and 10,000 users could have
  billions of ACL entries.
- **Inconsistency** -- Decentralized ACL management (where each resource owner manages their
  own) leads to inconsistent access patterns across the organization.
- **Audit Difficulty** -- Answering "what can Alice access?" requires scanning the ACL of
  every resource in the system -- extremely expensive at scale.
- **No Context** -- ACLs cannot express conditions like "only during business hours" or
  "only from managed devices."
- **Orphaned Entries** -- When users leave the organization, their ACL entries across all
  resources must be individually cleaned up.
- **Permission Creep** -- Over time, ACLs accumulate entries as access is granted but
  rarely revoked, violating least privilege.

---

## When to Use ACLs

**Use ACLs when:**

- You have a resource-centric system where users share specific objects (documents, files,
  folders, records).
- Resource owners need to control their own sharing (self-service model).
- The number of resources per user is moderate (hundreds, not millions).
- You are building a collaboration platform (document sharing, project management).
- You need to support ad-hoc, per-object permissions that do not map to predefined roles.

**Avoid ACLs when:**

- You have millions of resources and need to manage access at scale (prefer RBAC or ABAC).
- Access patterns are role-based and uniform across resource types.
- You need context-aware access decisions (prefer ABAC).
- You need a global view of "who can access what" for compliance (prefer RBAC).
- You are dealing with API authorization rather than resource sharing.

---

## Implementation Considerations

### Database Schema

```
resources                    acl_entries
+----+-----------------+     +----+---------+-----------+-----------+--------+
| id | name            |     | id | res_id  | subj_type | subj_id   | perms  |
+----+-----------------+     +----+---------+-----------+-----------+--------+
| 1  | budget.xlsx     |     | 1  | 1       | user      | alice     | rwds   |
| 2  | design.fig      |     | 2  | 1       | user      | bob       | rw     |
| 3  | /projects/alpha |     | 3  | 1       | group     | finance   | r      |
+----+-----------------+     | 4  | 2       | user      | alice     | rwds   |
                             | 5  | 3       | group     | eng-team  | rw     |
                             +----+---------+-----------+-----------+--------+

 Legend: r=read, w=write, d=delete, s=share
```

### Efficient Lookup Patterns

The most common query is: **"Does user X have permission P on resource R?"**

```
INDEX: (resource_id, subject_id)   -- fast per-resource, per-user lookup
INDEX: (subject_id)                 -- fast "what can this user access?" (if needed)
```

For systems with group membership, the lookup expands:

```python
def check_access(user_id, resource_id, permission):
    # Direct user entry
    entry = db.query(
        "SELECT perms FROM acl_entries WHERE res_id = ? AND subj_type = 'user' AND subj_id = ?",
        resource_id, user_id
    )
    if entry and permission in entry.perms:
        return ALLOW

    # Group entries
    user_groups = get_groups_for_user(user_id)
    entries = db.query(
        "SELECT perms FROM acl_entries WHERE res_id = ? AND subj_type = 'group' AND subj_id IN (?)",
        resource_id, user_groups
    )
    for entry in entries:
        if permission in entry.perms:
            return ALLOW

    return DENY
```

### Inheritance Strategy

For hierarchical resources (folders/files), two common strategies:

1. **Stored Inheritance** -- When a child is created, copy the parent's ACL entries and mark
   them as inherited. Pros: Fast reads. Cons: Expensive propagation on parent ACL changes.

2. **Walk-Up Evaluation** -- At access time, walk up the resource tree checking each level's
   ACL until a decision is reached. Pros: Cheap writes. Cons: Slower reads (mitigated by caching).

```
Strategy 1: Stored Inheritance

  /projects/ ACL: [@eng: rw]
       |
       +-- /projects/alpha/ ACL: [@eng: rw (inherited)]
               |                  [dave: manage (explicit)]
               +-- spec.md ACL: [@eng: rw (inherited)]
                                [dave: manage (inherited)]

  On parent change: Must update ALL descendants (recursive)

Strategy 2: Walk-Up Evaluation

  check_access(user, "/projects/alpha/spec.md", "read"):
    1. Check ACL on spec.md          -> no explicit entry
    2. Check ACL on /projects/alpha/  -> no match
    3. Check ACL on /projects/        -> @eng: rw -> user in @eng? -> ALLOW
```

### Caching

ACL lookups can be expensive. Common caching strategies:

- **Per-resource ACL cache** -- Cache the full ACL for frequently accessed resources.
- **Decision cache** -- Cache the result of (user, resource, permission) tuples.
- **Negative cache** -- Cache "no access" decisions to short-circuit repeated denied requests.
- **Invalidation** -- Invalidate on ACL change. For inherited ACLs, invalidate the subtree.

---

## ACL vs. Capability Lists

ACLs are resource-centric. The inverse is a **capability list**, which is subject-centric:

```
ACL (attached to resource):               Capability List (attached to subject):

Resource: budget.xlsx                      User: Alice
  Alice -> read, write                       budget.xlsx -> read, write
  Bob   -> read                              design.fig  -> read, write, delete
  Carol -> read                              spec.md     -> read

Resource: design.fig                       User: Bob
  Alice -> read, write, delete               budget.xlsx -> read
  Dave  -> read                              spec.md     -> read
```

| Dimension              | ACL (Resource-centric)  | Capability (Subject-centric) |
|------------------------|-------------------------|------------------------------|
| "Who can access this?" | Direct lookup           | Must scan all subjects       |
| "What can Alice access?"| Must scan all resources | Direct lookup                |
| Revocation             | Easy (edit resource ACL)| Hard (must find all copies)  |
| Delegation             | Hard                    | Easy (pass capability)       |

Most real systems use ACLs because revocation is more important than delegation in
enterprise contexts.

---

## Comparison with Other Models

| Dimension              | ACL                   | RBAC                | ABAC                 |
|------------------------|-----------------------|---------------------|----------------------|
| Attached to            | Resource              | User (via roles)    | Policy (evaluated)   |
| Granularity            | Per-resource          | Per-role            | Per-attribute combo  |
| Best for               | Sharing / collab      | Org structure       | Complex conditions   |
| Scalability            | Poor at scale         | Good                | Excellent            |
| "Who has access?"      | Read the ACL          | Check role members  | Simulate policies    |
| "What can user access?"| Scan all ACLs (slow)  | Check user's roles  | Simulate policies    |
| Context-aware          | No                    | No                  | Yes                  |
| Self-service sharing   | Yes (natural)         | No (needs admin)    | Possible but complex |
| Implementation effort  | Medium                | Low                 | High                 |

---

## Key Takeaways

1. ACLs attach a **permission list to each resource**, specifying which subjects can do what.
2. They are the most natural model for **sharing and collaboration** scenarios.
3. ACL inheritance enables manageable permission propagation in hierarchical structures.
4. ACLs struggle at scale -- millions of resources with complex access patterns overwhelm
   the model.
5. Google Drive, UNIX permissions, NTFS, and S3 are prominent ACL implementations.
6. For large-scale systems, ACLs are often combined with RBAC (group-based entries) or
   ABAC (conditional rules) to overcome their limitations.

---

## Further Reading

- POSIX.1e Draft Standard (ACLs for UNIX): https://www.usenix.org/legacy/events/usenix03/tech/freenix03/gruenbacher.html
- Google Zanzibar Paper (2019): "Zanzibar: Google's Consistent, Global Authorization System"
  (relationship-based ACLs at Google-scale)
- Windows NTFS ACL Reference: https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists
- S3 ACL Documentation: https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html
