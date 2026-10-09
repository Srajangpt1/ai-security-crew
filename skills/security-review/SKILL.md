---
name: security-review
description: >
  Pre-coding security assessment for any development task. Use this skill whenever the user
  is about to start coding a feature and wants to know the security requirements, risks, or
  considerations first — even if they don't say "security review" explicitly. Trigger on phrases
  like "before I code this", "what are the security requirements for", "security considerations
  for", "is this secure to build", "what should I watch out for when building", or when a user
  describes a feature (login, payments, file upload, API, auth, etc.) and asks how to approach it
  safely. Also trigger when user asks to "vibe code" securely or mentions they want security built
  in from the start.
---

Perform a pre-coding security review for the following task:

$ARGUMENTS

---

## What to do

Analyze the task description above and produce a structured security assessment. If no task description was provided in the arguments, ask the user to describe what they are building and optionally their tech stack before proceeding.

### Step 1 — Identify Technologies

Detect technologies from the description:
- Languages: Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, Rust, C#
- Frameworks: Django, FastAPI, Flask, Express, Next.js, Spring, Rails, Laravel
- Databases: PostgreSQL, MySQL, MongoDB, Redis, SQLite, DynamoDB
- Auth: JWT, OAuth2, SAML, session-based, API keys
- Infrastructure: AWS, GCP, Azure, Docker, Kubernetes
- Other: GraphQL, REST API, gRPC, WebSockets, message queues

### Step 2 — Assess Risk Level

**Critical** — payments/financial transactions, healthcare/PHI, authentication system, cryptographic key management, admin functionality, multi-tenant data isolation

**High** — PII collection/storage, file uploads, external API integrations, session management, password handling, OAuth flows, database schema changes

**Medium** — user-generated content, search functionality, data exports, email/notification systems, third-party SDKs, internal APIs

**Low** — static content, read-only public data, internal tooling with no sensitive data

### Step 3 — Identify Security Categories

Select all applicable:
- `authentication` — login, registration, password reset, MFA
- `authorization` — access control, roles, permissions, IDOR
- `data_validation` — input validation, sanitization, output encoding
- `cryptography` — encryption, hashing, key management, TLS
- `api_security` — endpoints, rate limiting, CORS, versioning
- `web_security` — XSS, CSRF, clickjacking, CSP
- `database` — SQL injection, ORM, connection security
- `secrets_management` — credentials, env vars, vaults
- `error_handling` — information disclosure, stack traces
- `logging` — audit trails, sensitive data in logs
- `cloud_security` — IAM, S3 permissions, VPC, security groups
- `supply_chain_security` — dependencies, lockfiles

### Step 4 — Apply Security Guidelines

For each identified category, provide specific, actionable guidance:

**Authentication:** Use bcrypt/argon2 for passwords; implement account lockout; secure HttpOnly SameSite cookies; rotate session tokens after login; enforce MFA for high-privilege actions.

**Authorization:** Validate permissions server-side on every request; deny-by-default; avoid direct object references; check ownership before granting access.

**Data Validation:** Validate and sanitize ALL user input server-side; use allowlists not denylists; encode output based on context (HTML, JS, SQL, URL); validate file uploads by type, size, and content.

**Cryptography:** AES-256-GCM or ChaCha20-Poly1305 for encryption; SHA-256+ for hashing (never MD5/SHA1 for security); cryptographically secure random for tokens; never hardcode keys.

**API Security:** Authenticate all sensitive endpoints; rate limit per user and per IP; validate Content-Type; return generic error messages (no stack traces in production); HTTPS + HSTS.

**Injection Prevention:** Parameterized queries/prepared statements for SQL; avoid eval()/exec() with user input; subprocess with shell=False (Python); sanitize data in OS commands, LDAP, XML, HTML.

**Secrets Management:** Never commit secrets to git; use environment variables or secrets manager (Vault, AWS SSM); rotate credentials regularly; scan commits for accidental exposure.

### Step 5 — Output

Produce this exact structure:

---

## Pre-Coding Security Review

**Task:** [task description]
**Risk Level:** [LOW | MEDIUM | HIGH | CRITICAL]
**Tech Stack Detected:** [list or "not specified"]
**Security Categories:** [comma-separated list]

### Risk Summary
[2–3 sentences explaining why this risk level was assigned and what the primary security concerns are for this specific task]

### Security Requirements

For each identified category:

#### [Category Name]
- [Specific requirement 1 — concrete, not generic]
- [Specific requirement 2]

### Pre-Coding Checklist
- [ ] [Check 1 — most critical for this task]
- [ ] [Check 2]
- [ ] [Check N — aim for 5–8 checks, task-specific]

### Prompt Injection for AI Code Generation

Copy this into your prompt when asking an AI to generate code for this task:

```
SECURITY REQUIREMENTS — apply throughout all generated code:

Risk Level: [RISK LEVEL]

[Bulleted list of the top 5–7 security requirements written as direct instructions to an AI code generator, specific to this task]
```
