# Attribute-Based Access Control (ABAC)

## Introduction

Attribute-Based Access Control (ABAC) is a flexible, fine-grained authorization model that
makes access decisions by evaluating **attributes** -- properties of the user, the resource,
the action, and the environment. Rather than assigning users to static roles, ABAC defines
**policies** that combine attributes using Boolean logic to determine whether a request
should be allowed or denied.

ABAC was formalized by NIST in Special Publication 800-162 (2014) and is the model behind
standards like XACML (eXtensible Access Control Markup Language). It is sometimes called
Policy-Based Access Control (PBAC) or Claims-Based Access Control.

The key advantage of ABAC is expressiveness. Where RBAC can say "Editors can edit articles,"
ABAC can say "Users in the Engineering department can edit articles they created, but only
during business hours, and only if the article is not classified as Confidential." This
kind of nuanced policy is impossible with RBAC alone.

---

## Core Concepts

### The Four Attribute Categories

| Category              | Description                                     | Examples                                   |
|-----------------------|-------------------------------------------------|--------------------------------------------|
| **Subject Attributes**| Properties of the user making the request       | department, clearance_level, role, title   |
| **Resource Attributes**| Properties of the object being accessed         | owner, classification, creation_date, type |
| **Action Attributes** | Properties of the operation being performed     | read, write, delete, approve               |
| **Environment Attributes**| Contextual properties of the request        | time_of_day, ip_address, device_trust, risk_score |

### Policy Structure

An ABAC policy is a rule that combines attributes with logical operators:

```
PERMIT action ON resource
  WHEN subject.department == resource.department
  AND   subject.clearance_level >= resource.classification
  AND   environment.time BETWEEN "09:00" AND "17:00"
  AND   environment.device_trust_level >= "managed"
```

---

## How It Works (Step by Step)

1. **Define Attributes** -- Catalog all relevant attributes for subjects, resources, actions,
   and the environment. Establish attribute sources (IdP, resource metadata, context services).

2. **Write Policies** -- Express access rules as attribute-based conditions. Policies can be
   PERMIT rules, DENY rules, or both with conflict resolution strategies.

3. **Request Arrives** -- A user (subject) attempts an action on a resource. The system
   collects attributes from all four categories.

4. **Policy Evaluation** -- The Policy Decision Point (PDP) evaluates all applicable policies
   against the collected attributes and produces an ALLOW or DENY decision.

5. **Enforcement** -- The Policy Enforcement Point (PEP) enforces the decision by allowing
   or blocking the request.

6. **Logging** -- The decision, the policies evaluated, and the attribute values used are
   logged for audit purposes.

---

## ABAC Architecture (ASCII Diagram)

```
                              ABAC ARCHITECTURE (XACML Reference)

   +----------+        (1) Access Request         +-----------------------+
   |  User    |  -------------------------------->|  Policy Enforcement   |
   |  (Alice) |                                   |  Point (PEP)          |
   +----------+                                   +-----------+-----------+
        ^                                                     |
        |           (5) Allow / Deny                          | (2) Decision Request
        +-----------------------------------------------------+   (subject, action,
                                                              |    resource, env attrs)
                                                              v
                                                  +-----------+-----------+
                                                  |  Policy Decision      |
                                                  |  Point (PDP)          |
                                                  +-----------+-----------+
                                                     |     ^       |
                                        (3) Fetch    |     |       | (3) Fetch
                                        policies     |     |       | attributes
                                                     v     |       v
                                            +--------+-+  ++-------+--------+
                                            | Policy   |  | Policy          |
                                            | Admin    |  | Information     |
                                            | Point    |  | Point (PIP)     |
                                            | (PAP)    |  +-----------------+
                                            +----------+    |    |       |
                                            (where policies |    |       |
                                             are authored)  v    v       v
                                                         +----+ +----+ +-------+
                                                         | HR | | AD | | Asset |
                                                         | DB | |/IdP| | DB    |
                                                         +----+ +----+ +-------+

  ATTRIBUTE FLOW:
  +---------------------------------------------------------------------------+
  | Subject Attrs     | Resource Attrs       | Action   | Environment Attrs   |
  |-------------------|----------------------|----------|---------------------|
  | user: alice       | resource: doc-42     | action:  | time: 14:30 UTC     |
  | dept: engineering | owner: alice         |   read   | ip: 10.0.1.50       |
  | clearance: secret | classification: conf |          | device: managed     |
  | title: senior_eng | project: phoenix     |          | risk_score: low     |
  +---------------------------------------------------------------------------+
                              |
                              v
  +-------------------------------------------------------------------+
  | POLICY EVALUATION                                                  |
  |                                                                    |
  | Rule 1: PERMIT read ON documents                                   |
  |   WHERE subject.dept == resource.project.dept      => TRUE         |
  |   AND   subject.clearance >= resource.classification => TRUE       |
  |   AND   environment.device == "managed"              => TRUE       |
  |                                                                    |
  | Result: PERMIT                                                     |
  +-------------------------------------------------------------------+
```

---

## Policy Examples

### Example 1: Department-Scoped Access

```
Policy: "Department Document Access"
Target:  action IN [read, write]
         resource.type == "document"

Rule:    PERMIT
         WHEN subject.department == resource.department
         AND  subject.employment_status == "active"
```

### Example 2: Time-Restricted Admin Access

```
Policy: "After-Hours Restriction"
Target:  subject.role == "admin"

Rule:    DENY
         WHEN environment.hour < 6 OR environment.hour > 22
         AND  environment.location NOT IN ["office_vpn"]
```

### Example 3: Data Classification Enforcement

```
Policy: "Classification Clearance"
Target:  resource.classification IN ["confidential", "top_secret"]

Rule:    PERMIT
         WHEN subject.clearance_level >= resource.classification_level
         AND  environment.device_trust >= "high"
         AND  environment.mfa_verified == true
```

---

## Real-World Examples

### Firebase Security Rules (RBAC + ABAC Hybrid)

Firebase is one of the best examples of ABAC in a consumer-facing product. Its security
rules evaluate attributes of the request, the authenticated user, and the data itself:

```javascript
// Firestore Security Rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /posts/{postId} {
      // Only the author can update their own posts
      allow update: if request.auth.uid == resource.data.authorId
                    && request.time < resource.data.editDeadline;

      // Anyone can read published posts
      allow read: if resource.data.status == "published";

      // Admins can do anything
      allow read, write: if request.auth.token.admin == true;
    }
  }
}
```

This combines:
- **Subject attributes**: `request.auth.uid`, `request.auth.token.admin`
- **Resource attributes**: `resource.data.authorId`, `resource.data.status`
- **Environment attributes**: `request.time`

### AWS IAM Policies (Condition Keys)

AWS IAM policies use ABAC through **condition keys**:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::project-*",
  "Condition": {
    "StringEquals": {
      "s3:ExistingObjectTag/Department": "${aws:PrincipalTag/Department}"
    },
    "IpAddress": {
      "aws:SourceIp": "203.0.113.0/24"
    }
  }
}
```

This says: "Allow S3 reads only when the object's Department tag matches the user's
Department tag AND the request comes from a specific IP range."

### Google Cloud IAP (Identity-Aware Proxy)

Google's IAP evaluates user identity, device security posture, and network context to
make access decisions -- a textbook ABAC implementation for zero-trust architectures.

### Microsoft Azure ABAC

Azure Storage supports ABAC conditions on role assignments, enabling rules like
"Storage Blob Data Reader can read blobs only when the blob's Project tag matches the
user's Project attribute."

---

## Pros and Cons

### Advantages

- **Extreme Flexibility** -- Can express virtually any access policy imaginable.
- **Fine-Grained** -- Decisions can consider individual resource properties, not just types.
- **Context-Aware** -- Environmental attributes enable dynamic, risk-adaptive access control.
- **No Role Explosion** -- A single policy can replace dozens of RBAC roles.
- **Dynamic** -- Policies adapt automatically as attributes change (e.g., user changes department).
- **Externalized** -- Policies can be managed independently of application code.

### Disadvantages

- **Complexity** -- Writing, testing, and debugging attribute-based policies is significantly
  harder than managing roles.
- **Performance** -- Collecting attributes from multiple sources and evaluating complex
  policies adds latency. Caching and optimization are critical.
- **Auditability Challenges** -- Answering "who can access this resource?" requires simulating
  policy evaluation across all possible attribute combinations -- much harder than listing
  role assignments.
- **Attribute Management** -- Requires a reliable, consistent source of truth for all
  attributes. Stale or incorrect attributes lead to wrong decisions.
- **Steep Learning Curve** -- Teams need training on policy languages (XACML, Rego, Cedar).
- **Testing Difficulty** -- The combinatorial explosion of attribute values makes exhaustive
  testing impractical.

---

## When to Use ABAC

**Use ABAC when:**

- Access decisions depend on properties of the resource (ownership, classification, tags).
- Environmental context matters (time, location, device, risk score).
- You have too many distinct access patterns for RBAC roles to cover without explosion.
- You operate in a regulated industry requiring fine-grained, auditable access policies.
- You are implementing zero-trust architecture where every request is evaluated dynamically.
- You need cross-organizational access control (federated systems).

**Avoid ABAC when:**

- Your access model is simple enough for RBAC (a handful of roles cover all cases).
- You lack reliable attribute sources or the infrastructure to collect attributes at request time.
- Your team does not have the expertise to write and maintain policy rules.
- Performance is extremely latency-sensitive and you cannot afford policy evaluation overhead.

---

## Implementation Considerations

### Policy Languages and Engines

| Engine / Language     | Description                                              |
|-----------------------|----------------------------------------------------------|
| **XACML**            | XML-based standard. Very expressive, very verbose.       |
| **OPA / Rego**       | Open Policy Agent. Policies in Rego (Datalog-inspired).  |
| **Cedar**            | By AWS (used in Amazon Verified Permissions). Typed, fast.|
| **Casbin**           | Library supporting RBAC, ABAC, and hybrid models.        |
| **Open FGA**         | Relationship-based access control (ReBAC) by Auth0/Okta. |

### Architecture Decisions

1. **Centralized vs. Distributed PDP** -- A centralized PDP is easier to manage but becomes
   a bottleneck. Distributed (sidecar) PDPs scale better but require policy synchronization.

2. **Attribute Caching** -- Cache subject and resource attributes aggressively. Use
   event-driven invalidation (e.g., user department changes triggers cache eviction).

3. **Policy Versioning** -- Treat policies as code. Store them in version control, review
   changes via pull requests, and deploy through CI/CD.

4. **Default Deny** -- Always start with a default-deny posture. Only explicit PERMIT
   policies should grant access.

5. **Conflict Resolution** -- When multiple policies apply, you need a combining algorithm:
   - **Deny-overrides**: Any DENY wins.
   - **Permit-overrides**: Any PERMIT wins.
   - **First-applicable**: The first matching policy wins.

### Performance Optimization

```
                        Request Latency Budget: 5ms

  +-------------------+-------------------+--------------------+
  | Attribute Fetch   | Policy Evaluation | Enforcement        |
  | (cached: <1ms)    | (in-memory: <1ms) | (inline: <0.1ms)  |
  +-------------------+-------------------+--------------------+
  |<--- Target: < 2ms total decision time --->|

  Strategy:
  - Pre-load policies into memory (OPA bundles, Cedar policy stores)
  - Cache subject attributes in JWT claims
  - Cache resource attributes at the service level
  - Use bloom filters for quick "definitely not allowed" checks
```

---

## Comparison with Other Models

| Dimension              | ABAC                  | RBAC                | ACL                  |
|------------------------|-----------------------|---------------------|----------------------|
| Decision basis         | Attributes + policies | Role membership     | Per-object entries   |
| Granularity            | Very fine             | Coarse to medium    | Very fine            |
| Context-awareness      | Yes (first-class)     | No                  | No                   |
| Policy expressiveness  | Very high             | Low                 | Low                  |
| Scalability (policies) | Excellent             | Poor (role explosion)| Poor                 |
| Auditability           | Hard                  | Easy                | Medium               |
| Implementation cost    | High                  | Low                 | Medium               |
| Maintenance            | Moderate (policies)   | Moderate (roles)    | High (per-object)    |

---

## Key Takeaways

1. ABAC evaluates **attributes** of the subject, resource, action, and environment to make
   access decisions -- enabling policies of arbitrary complexity.
2. It solves the **role explosion** problem inherent in RBAC by expressing policies declaratively.
3. The XACML architecture (PEP, PDP, PAP, PIP) provides a clean separation of concerns.
4. Real-world systems (Firebase, AWS IAM, Azure) increasingly adopt ABAC or hybrid models.
5. The tradeoff is complexity: ABAC requires careful attribute management, policy testing,
   and performance optimization.
6. In practice, most production systems use a **hybrid RBAC+ABAC** model -- RBAC for coarse
   access control, ABAC for fine-grained conditional rules.

---

## Further Reading

- NIST SP 800-162: "Guide to Attribute Based Access Control (ABAC) Definition and Considerations"
- OASIS XACML 3.0 Standard: http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html
- AWS Cedar Language: https://www.cedarpolicy.com/
- Open Policy Agent: https://www.openpolicyagent.org/
