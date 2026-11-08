# nest-auth

nest-auth is a production-grade authentication service for NestJS. It provides
argon2id password hashing, short-lived JWT access tokens paired with rotating
opaque refresh tokens, Redis-backed token revocation, and Google OAuth — with
account enumeration closed off at every endpoint that handles a credential.

---

## Features

| Capability              | Implementation                                                                |
| ----------------------- | ----------------------------------------------------------------------------- |
| **Password hashing**    | argon2id at RFC 9106's recommended parameters — 19 MiB, t=2, p=1              |
| **Access tokens**       | HS256 JWT, 15 min TTL, unique `jti` per token, issuer and expiry validated    |
| **Refresh tokens**      | Opaque 32-byte tokens stored as SHA-256 digests, rotated per session          |
| **Revocation**          | Redis blacklist keyed by `jti`, TTL-matched so entries self-expire            |
| **OAuth 2.0**           | Google sign-in over OIDC with PKCE and `state`, provider-agnostic schema      |
| **Enumeration defense** | Identical responses and constant-time paths for unknown and wrong credentials |
| **Rate limiting**       | Redis-backed attempt counters per IP and per account                          |
| **Session control**     | Revoke one session or every session for a user                                |
| **Hardening**           | Helmet, CORS allowlist, global DTO whitelist, Zod-validated environment       |
| **Observability**       | NestJS Observe — traces, metrics, correlated logs, error tracking             |

---

## Why argon2id

Passwords are hashed with **argon2id**, the hybrid variant standardized in
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) and the first entry in the
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html):

```ts
type: argon2id,
memoryCost: 19456, // 19 MiB
timeCost: 2,       // passes over memory
parallelism: 1,    // lanes
```

That is precisely RFC 9106's second recommended option and the OWASP minimum
for argon2id.

The advantage is **memory hardness**. A GPU computes SHA-256 orders of magnitude
faster than a CPU, and commodity password-cracking hardware is built from GPUs.
An algorithm that is cheap in memory is cheap to attack in parallel. Argon2 spends
19 MiB of RAM per guess, so an attacker must provision memory proportional to
their parallel throughput — and GPUs have abundant compute but limited memory
bandwidth. That asymmetry is the point.

Argon2id is the hybrid of the two Argon2 variants: Argon2d's resistance to
time-memory trade-off attacks, plus Argon2i's data-independent memory access,
which keeps it safe against cache-timing observation of the hashing process.

| Algorithm      | Memory-hard | Weakness                                                        |
| -------------- | ----------- | --------------------------------------------------------------- |
| SHA-256 + salt | No          | Trivially parallelized on GPUs                                  |
| PBKDF2         | No          | Cheap per iteration, so GPU throughput scales near-linearly     |
| bcrypt         | No          | CPU-hard only, and truncates input at 72 bytes                  |
| scrypt         | Yes         | Sound, but weaker on trade-off attacks and less mature guidance |
| **argon2id**   | **Yes**     | **Current OWASP recommendation**                                |

Each hash embeds its own random salt, so two users with the same password get
different digests and precomputed rainbow tables are useless. Verification runs
through argon2's constant-time comparison. Digests record the parameters they
were created with, so cost can be raised transparently on a user's next
successful login.

---

## Defense in depth

**Login does not reveal whether an account exists.** A missing account is
verified against a dummy argon2 hash before the failure is returned, so "no such
user" costs the same as "wrong password" — roughly 17 ms either way. Without
that, the timing gap is a reliable enumeration oracle even when both responses
look identical in the body.

**Access tokens are short-lived and individually revocable.** 15 minutes bounds
the damage from a token that leaks out of a browser, a log, or a shared link.
Each carries a unique `jti`, which is what lets one session be killed without
touching the user's other sessions.

**Refresh tokens are opaque and stored as digests.** 32 random bytes in
base64url, persisted only as a SHA-256 hash — a dump of the table cannot be
replayed against the server. A `session_id` groups every token minted from one
login, so a family can be revoked in a single operation, and `revoked_at` plus
`revoked_reason` leave an audit trail of why a token died.

**Redis carries the hot paths.** The blacklist is keyed by `jti` with a TTL
equal to the token's remaining lifetime, so it expires on its own with no
cleanup job. Redis also holds session registries, login attempt counters, and
short-lived OAuth `state` values. It is a better fit than Postgres for all of
these: O(1) lookups, native expiry, and operations that must be atomic can run
as Lua scripts instead of racing between round trips.

**OAuth is provider-agnostic.** The third-party identity lives in its own table
rather than as columns on `user`, so adding a provider is a new strategy and a
new row type — not a schema migration. The local `user` row stays the single
source of truth for the account.

**The perimeter is hardened.** Helmet sets the security headers, CORS is an
explicit allowlist, the global `ValidationPipe` rejects unknown properties
outright rather than passing them through, and Zod validates the environment at
boot so a missing variable or a weak secret fails the process immediately
instead of at 3am.

---

## Data model

| Table            | Purpose                                                                      |
| ---------------- | ---------------------------------------------------------------------------- |
| `user`           | Local account: email, nullable password hash, verification state, timestamps |
| `oauth_account`  | Links a third-party provider identity to a local user                        |
| `refresh_tokens` | Hashed refresh tokens, grouped by session, with revocation metadata          |

Entities live beside the module that owns them and are registered in
`src/database/entities.ts`. Schema changes go through TypeORM migrations:

```bash
npm run migration:generate -- src/database/migrations/AddSomething
npm run migration:run
npm run migration:revert
```

---

## API

| Method | Path                        | Auth    | Description                                      |
| ------ | --------------------------- | ------- | ------------------------------------------------ |
| `POST` | `/api/auth/register`        | —       | Create an account, returns an access token       |
| `POST` | `/api/auth/login`           | —       | Exchange credentials for an access token         |
| `POST` | `/api/auth/refresh`         | refresh | Rotate a refresh token, issue a new access token |
| `POST` | `/api/auth/logout`          | bearer  | Revoke the current session                       |
| `GET`  | `/api/auth/me`              | bearer  | Return the authenticated user                    |
| `GET`  | `/api/auth/google`          | —       | Begin Google sign-in                             |
| `GET`  | `/api/auth/google/callback` | —       | Google redirect target                           |
| `GET`  | `/api/health`               | —       | Liveness check                                   |
| `GET`  | `/docs`                     | —       | Swagger UI                                       |

All routes carry the `API_PREFIX` prefix, default `api`.

---

## Getting started

**Requirements:** Node.js 20+, Docker, Docker Compose.

```bash
# 1. Install dependencies
npm install

# 2. Configure the environment
cp .env.example .env
# set JWT_ACCESS_SECRET to 48+ random bytes
openssl rand -base64 48

# 3. Start the services
docker compose up -d
# Postgres on :5434 (database 'eauth'), pgAdmin on :5051
docker run -d --name nest-auth-redis -p 6379:6379 redis:7-alpine
# Redis on :6379

# 4. Create the schema
npm run migration:run

# 5. Run it
npm run start:dev
```

Then: API on <http://localhost:3000/api> · Swagger UI on
<http://localhost:3000/docs> · health check on
<http://localhost:3000/api/health>.

### Environment

| Variable                                                                                        | Purpose                                            |
| ----------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| `DATABASE_URL`                                                                                  | Postgres connection URL, validated at boot         |
| `DATABASE_HOST` / `DATABASE_PORT` / `DATABASE_USERNAME` / `DATABASE_PASSWORD` / `DATABASE_NAME` | Discrete connection settings used by TypeORM       |
| `JWT_ACCESS_SECRET`                                                                             | Access token signing secret, minimum 32 characters |
| `JWT_ACCESS_TTL` / `JWT_REFRESH_TTL`                                                            | Token lifetimes, default `15m` and `30d`           |
| `JWT_ISSUER`                                                                                    | Expected `iss` claim                               |
| `REDIS_HOST` / `REDIS_PORT` / `REDIS_PASSWORD`                                                  | Redis connection settings                          |
| `CORS_ORIGINS`                                                                                  | Comma-separated allowlist                          |
| `OBSERVE_APP_KEY` / `OBSERVE_APP_SECRET`                                                        | NestJS Observe credentials                         |

---

## Layout

```
src/
├── common/            # @CurrentUser decorator, duration/email/opaque-token utils
├── configs/           # typed, validated configuration
├── database/          # entity registry, migrations, CLI data source
├── modules/
│   ├── auth/          # controller, service, argon2, tokens, strategies, guards, DTOs
│   └── users/         # user entity, service, response DTO
├── health/            # liveness endpoint
└── main.ts            # bootstrap, helmet, CORS, validation, Swagger
```

---

## Scripts

| Command                                                     | Description               |
| ----------------------------------------------------------- | ------------------------- |
| `npm run start` / `start:dev` / `start:prod`                | Run the service           |
| `npm run build`                                             | Compile to `dist/`        |
| `npm run lint` / `npm run format`                           | oxlint and prettier       |
| `npm test` / `npm run test:e2e`                             | Unit and end-to-end tests |
| `npm run migration:generate` / `:run` / `:revert` / `:show` | Schema migrations         |

---

## License

Unlicensed and private. `package.json` declares `private: true` with
`license: UNLICENSED`, so the code is not licensed for redistribution.
