Perform a pre-coding security review for the following task:

$ARGUMENTS

---

## Instructions

Analyze the task description above and produce a structured security assessment. If no task is provided, ask the user to describe what they are building and optionally their tech stack.

### Step 1 — Identify Technologies

Detect technologies from the description. Look for:
- Languages: Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, Rust, C#
- Frameworks: Django, FastAPI, Flask, Express, Next.js, Spring, Rails, Laravel
- Databases: PostgreSQL, MySQL, MongoDB, Redis, SQLite, DynamoDB
- Auth: JWT, OAuth2, SAML, session-based, API keys
- Infrastructure: AWS, GCP, Azure, Docker, Kubernetes
- Other: GraphQL, REST API, gRPC, WebSockets, message queues

### Step 2 — Assess Risk Level

Determine risk level based on what the task involves:

**Critical** — Any of: payments/financial transactions, healthcare/PHI, authentication/auth system, cryptographic key management, admin functionality, privilege escalation, multi-tenant data isolation

**High** — Any of: PII collection/storage, file uploads, external API integrations, session management, password handling, OAuth flows, database schema changes, rate limiting

**Medium** — Any of: user-generated content, search functionality, data exports, email/notification systems, third-party SDKs, internal APIs

**Low** — Static content, read-only public data, internal tooling with no sensitive data

### Step 3 — Identify Security Categories

Select all applicable categories from this list:
- `authentication` — login, registration, password reset, MFA
- `authorization` — access control, roles, permissions, IDOR
- `data_validation` — input validation, sanitization, output encoding
- `cryptography` — encryption, hashing, key management, TLS
- `api_security` — endpoints, rate limiting, CORS, versioning
- `web_security` — XSS, CSRF, clickjacking, CSP, SRI
- `database` — SQL injection, ORM, connection security, migrations
- `secrets_management` — credentials, env vars, vaults, rotation
- `error_handling` — information disclosure, stack traces, error codes
- `logging` — audit trails, sensitive data in logs, monitoring
- `cloud_security` — IAM, S3 permissions, VPC, security groups
- `supply_chain_security` — dependencies, lockfiles, package integrity

### Step 4 — Generate Security Guidelines

For each identified security category, provide:
- Specific threats relevant to the task
- Mitigation recommendations
- Code-level guidance (what to do / what to avoid)

Base guidelines on these principles:

**Authentication:**
- Use bcrypt/argon2 for password hashing (never MD5/SHA1)
- Implement account lockout and brute force protection
- Use secure, HttpOnly, SameSite cookies for sessions
- Rotate session tokens after login
- Enforce MFA for high-privilege actions

**Authorization:**
- Validate permissions server-side on every request
- Use deny-by-default access control
- Avoid direct object references — use indirect mappings
- Separate admin and user privilege levels
- Check ownership before granting resource access

**Data Validation:**
- Validate and sanitize ALL user input server-side
- Use allowlists, not denylists
- Encode output based on context (HTML, JS, SQL, URL)
- Validate file uploads: type, size, content (not just extension)

**Cryptography:**
- Use AES-256-GCM or ChaCha20-Poly1305 for encryption
- Use SHA-256+ for hashing (not MD5/SHA1 for security)
- Use cryptographically secure random for tokens/nonces
- Never hardcode keys — use environment variables or vaults

**API Security:**
- Authenticate all sensitive endpoints
- Apply rate limiting per user and per IP
- Validate Content-Type and reject unexpected formats
- Return generic error messages (no stack traces in production)
- Use HTTPS only; enforce HSTS

**Injection Prevention:**
- Use parameterized queries / prepared statements for SQL
- Avoid eval(), exec(), and dynamic code execution
- Use subprocess with shell=False (Python)
- Sanitize data used in OS commands, LDAP, XML, HTML

**Secrets Management:**
- Never commit secrets to version control
- Use environment variables or a secrets manager (Vault, AWS SSM)
- Rotate credentials regularly
- Scan commits for accidental secret exposure

### Step 5 — Output

Produce the following structured response:

---

## Pre-Coding Security Review

**Task:** [task description]
**Risk Level:** [LOW | MEDIUM | HIGH | CRITICAL]
**Tech Stack Detected:** [list]
**Security Categories:** [list]

### Risk Summary
[2-3 sentence explanation of why this risk level was assigned and what the primary concerns are]

### Security Requirements

For each category, list specific requirements:

#### [Category Name]
- [Requirement 1]
- [Requirement 2]
- [Requirement N]

### Security Checklist (use before submitting code)
- [ ] [Check 1]
- [ ] [Check 2]
- [ ] [Check N]

### Prompt Injection for AI Code Generation

When generating code for this task, include these instructions in your prompt to the AI:

```
SECURITY REQUIREMENTS — apply these throughout all generated code:

Risk Level: [RISK LEVEL]
Categories: [CATEGORIES]

[Bulleted list of the most important security requirements for this task, written as direct instructions to an AI code generator]
```

---
