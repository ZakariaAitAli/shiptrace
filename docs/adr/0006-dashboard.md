# ADR-0006: Server-rendered dashboard with separate named accounts

Status: Accepted by the owner, subject to security tests during P2 · Date: 2026-11-01

**Context.** A minimal, read-only web UI. The owner rejected signing in with API tokens: machine
credentials and human sign-in must stay separate. Enterprise IAM and RBAC are out of scope.

**Decision.**
- Jinja2 templates served by the same app, with no JavaScript build and a strict CSP.
- **Human identity is a small `dashboard_users` table**: `id, username, password_hash, disabled_at,
  created_at`. There are no roles: every account can view everything and change nothing.
- Accounts are created, reset and disabled only through the admin CLI. There is no self-service
  registration, email or password-reset flow.
- Passwords are hashed with Argon2id (`argon2-cffi`), minimum length 15, with no composition rules.
- Sign-in creates a server-side `dashboard_sessions` row and a `__Host-` cookie holding a random
  token; only its digest is stored. Disabling an account ends its sessions.
- Sign-in has its own rate limit by IP and username. Unknown usernames do equal hashing work.
- **API tokens cannot sign in, and session cookies cannot call the JSON API.** The two paths share
  no credential, so a leaked pipeline token never opens the UI, and a browser never holds a token.

**Why.** It separates the two credential types with one table and one CLI command, and adds no
outbound dependency. Argon2id is right here, unlike for API tokens, because human passwords are
low-entropy. Server-side sessions give real logout and need no signing key.

**Rejected.**
- *Pasted API token* (previous proposal): rejected by the owner.
- *GitHub OAuth with an allowlist*: no password storage and possibly the best long-term option, but
  adds an OAuth app, a client secret, outbound calls and ASVS V10. First candidate if accounts
  prove awkward.
- *Load-balancer OIDC*: needs AWS and an identity provider; useless locally.
- *HTTP Basic behind a reverse proxy*: no logout or session timeout.
- *SPA, stateless signed cookies*: a build pipeline, or logout that cannot invalidate a session.

**Consequences.** Passwords now exist, so ASVS V6.2 and 11.4.2 apply. No MFA, which stays a recorded
gap (6.3.3); the UI is read-only, which limits the impact. One more table and an `argon2-cffi`
dependency, both arriving in P2.
