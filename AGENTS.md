# AGENTS.md

## Purpose

This repository is a security-first fullstack template for building systems.

All contributors and coding agents must preserve the template's security model, service boundaries, and deployment contracts while extending domain features.

## Repository Scope

This template currently includes:
- React client behind nginx edge
- Node/Express services:
  - `auth-service`
  - `core-api`
  - `tools-service`
  - `reports-service`
- PostgreSQL persistence
- Redis-backed distributed auth rate limiting
- JWT + refresh rotation + CSRF protection
- Optional DPoP-bound session enforcement
- Optional TOTP MFA

## Non-Negotiable Architecture Rules

1. Preserve route ownership:
- `/api/auth/*`, `/api/profile/*`, `/api/audit/*`, `/api/settings/*` -> `auth-service`
- `/api/tools/*` -> `tools-service`
- `/api/reports/*` -> `reports-service`
- Remaining `/api/*` -> `core-api`

2. Keep nginx as the single public entrypoint for containerized deployments.

3. Keep private services and PostgreSQL on the internal Docker network.

4. Keep shared service bootstrap patterns in place:
- `server/src/utils/expressBootstrap.ts`
- `server/src/utils/startService.ts`
- `server/src/utils/gracefulShutdown.ts`

5. Keep migrations idempotent and additive in `server/src/db.ts`.

## Security Guardrails (Mandatory)

1. TLS policy:
- `deploy/nginx.conf` must enforce TLS 1.3 only.
- Keep explicit strong TLS 1.3 ciphersuite allowlist.
- Keep HTTP -> HTTPS redirect.

2. Authentication/session model:
- Access tokens are short-lived JWT (`HS256`) with `sid` and `tv` claims.
- Refresh tokens are cookie-based (`HttpOnly`, `Secure`, `SameSite=Strict`), not request-body tokens.
- Refresh rotation must occur on every successful refresh.
- Refresh token reuse detection must revoke session family and bump user token version.

3. CSRF:
- Refresh endpoint requires double-submit validation using `csrf_token` cookie + `X-CSRF-Token` header.

4. DPoP:
- For DPoP-bound sessions, require both:
  - `Authorization: DPoP <token>`
  - `DPoP: <proof>`
- Enforce proof signature, `htm`/`htu`, nonce, and replay checks.
- Keep nonce and replay state in shared storage (DB/Redis), never process memory only.

5. RBAC:
- Enforce permissions server-side on protected routes.
- Never rely on frontend-only route hiding.

6. Input and data handling:
- Validate request input with `zod`.
- Use parameterized SQL only.
- Never interpolate untrusted values into SQL.

7. Secret handling:
- No hardcoded production secrets.
- Keep MFA/other sensitive secrets encrypted at rest using `PSS_MASTER_KEY` path in `utils/secrets.ts`.

## Coding Standards

1. TypeScript strictness:
- Keep server TypeScript in strict mode.
- Do not bypass type safety with broad `any` unless justified and narrowly scoped.

2. Service boundaries:
- Place auth/session/identity logic in auth service modules.
- Keep core/tools/reports focused on their domain.

3. Reuse shared utilities:
- Prefer existing middleware/services over duplicate logic.
- Extend existing modules before creating parallel alternatives.

4. Error behavior:
- Keep generic production errors.
- Avoid leaking stack traces/secrets in API responses.

5. Auditability:
- Mutating or privileged operations should emit audit logs.

## Development Workflow

1. Branching:
- Use feature branches prefixed with `dev/`.

2. Dependency updates:
- Keep dependencies current, but do not mix security fixes and feature changes in one large commit.

3. Config changes:
- If adding/changing environment variables:
  - update `.env.example`
  - update `README.md`
  - update settings exposure endpoint if appropriate

4. API changes:
- Update route docs in `README.md` endpoint inventory when contracts change.

## Required Verification Before Merge

Run relevant checks from repository root:

1. Compose config validation:
```sh
docker compose config
```

2. Build images:
```sh
docker compose build
```

3. Server type/build checks:
```sh
cd server
npm install
npm run typecheck
npm run build
```

4. Client build checks:
```sh
cd client
npm install
npm run build
```

5. Smoke checks after boot:
```sh
docker compose up -d
curl -k https://localhost/api/health
curl -k https://localhost/api/components
```

If a check is skipped, document why in PR notes.

## Change-Specific Test Expectations

1. Auth/session changes:
- Test login, refresh, logout, forced logout.
- Test refresh reuse detection path.

2. DPoP changes:
- Test valid proof path.
- Test nonce challenge/retry path.
- Test replay rejection path.

3. MFA changes:
- Test enrollment start/verify.
- Test MFA challenge completion and lockout handling.

4. RBAC changes:
- Test both authorized and forbidden paths for each changed endpoint.

## Definition of Done

A change is done only when:
1. Architecture contracts are preserved.
2. Security guardrails above remain intact.
3. Build/type checks pass.
4. New/changed behavior is tested.
5. `README.md` is updated for any operational or API contract changes.

## Fast Start Commands

```sh
cp .env.example .env
mkdir -p deploy/certs
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout deploy/certs/tls.key \
  -out deploy/certs/tls.crt \
  -subj "/CN=localhost"
docker compose up --build
```

Access app at:
- `https://localhost`

## Notes for Future HR Productization

This repository is a secure starter, not a complete HR application.

When adding HR modules (employees, org hierarchy, leave, payroll interfaces, approvals):
- apply RBAC and ownership checks at API layer
- add audit events for all sensitive changes
- keep migrations additive and rollback-aware
- update operational runbooks in `README.md`
