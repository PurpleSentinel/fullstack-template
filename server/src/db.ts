import { Pool, PoolClient, QueryResult, QueryResultRow } from "pg";
import { config } from "./config";

let pool: Pool | undefined;

const getPool = (): Pool => {
  if (!pool) {
    pool = new Pool({
      host: config.db.host,
      port: config.db.port,
      user: config.db.user,
      password: config.db.password,
      database: config.db.database,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 5000
    });
  }

  return pool;
};

export const query = <T extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] = []
): Promise<QueryResult<T>> => {
  return getPool().query<T>(text, params);
};

export const all = async <T extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] = []
): Promise<T[]> => {
  const result = await query<T>(text, params);
  return result.rows;
};

export const get = async <T extends QueryResultRow = QueryResultRow>(
  text: string,
  params: unknown[] = []
): Promise<T | null> => {
  const rows = await all<T>(text, params);
  return rows[0] ?? null;
};

export const run = async (text: string, params: unknown[] = []): Promise<number> => {
  const result = await query(text, params);
  return result.rowCount ?? 0;
};

export const transaction = async <T>(fn: (client: PoolClient) => Promise<T>): Promise<T> => {
  const client = await getPool().connect();

  try {
    await client.query("BEGIN");
    const output = await fn(client);
    await client.query("COMMIT");
    return output;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
};

const migrations: string[] = [
  `CREATE EXTENSION IF NOT EXISTS pgcrypto;`,

  `CREATE TABLE IF NOT EXISTS roles (
    role_key TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );`,

  `CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    public_id UUID NOT NULL DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    email TEXT UNIQUE,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    token_version INTEGER NOT NULL DEFAULT 1,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    login_locked_until TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_totp_secret_cipher TEXT,
    mfa_pending_secret_cipher TEXT,
    mfa_pending_created_at TIMESTAMPTZ,
    mfa_last_used_step BIGINT,
    role TEXT NOT NULL REFERENCES roles(role_key),
    user_type TEXT NOT NULL DEFAULT 'application_user',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );`,

  `CREATE TABLE IF NOT EXISTS auth_sessions (
    sid UUID PRIMARY KEY,
    session_family_id UUID NOT NULL,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash TEXT NOT NULL,
    dpop_jkt TEXT,
    user_agent TEXT,
    source_ip TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );`,

  `ALTER TABLE auth_sessions ADD COLUMN IF NOT EXISTS session_family_id UUID;`,
  `UPDATE auth_sessions SET session_family_id = sid WHERE session_family_id IS NULL;`,
  `CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON auth_sessions(user_id);`,
  `CREATE INDEX IF NOT EXISTS idx_auth_sessions_family_id ON auth_sessions(session_family_id);`,
  `CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON auth_sessions(expires_at);`,

  `CREATE TABLE IF NOT EXISTS auth_mfa_challenges (
    challenge_id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    consumed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );`,

  `CREATE TABLE IF NOT EXISTS user_profiles (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    department TEXT,
    title TEXT,
    manager_user_id BIGINT REFERENCES users(id),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );`,

  `CREATE TABLE IF NOT EXISTS user_preferences (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );`,

  `CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT,
    username TEXT,
    role TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    http_method TEXT,
    http_path TEXT,
    status_code INTEGER,
    source_ip TEXT,
    user_agent TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );`,

  `CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);`,

  `CREATE TABLE IF NOT EXISTS dpop_replay_cache (
    jti TEXT NOT NULL,
    htu TEXT NOT NULL,
    htm TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (jti, htu, htm)
  );`,

  `CREATE TABLE IF NOT EXISTS dpop_nonces (
    nonce TEXT PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );`
];

const roleSeeds: Array<{ roleKey: string; displayName: string; permissions: string[] }> = [
  {
    roleKey: "hr_admin",
    displayName: "HR Admin",
    permissions: [
      "audit:read",
      "settings:read",
      "settings:write",
      "users:manage",
      "sessions:revoke",
      "profile:read",
      "profile:write",
      "reports:read",
      "tools:use"
    ]
  },
  {
    roleKey: "manager",
    displayName: "Manager",
    permissions: ["profile:read", "profile:write", "reports:read", "tools:use"]
  },
  {
    roleKey: "employee",
    displayName: "Employee",
    permissions: ["profile:read", "profile:write", "tools:use"]
  }
];

const MIGRATION_LOCK_KEY_1 = 81012;
const MIGRATION_LOCK_KEY_2 = 1;

export const migrate = async (): Promise<void> => {
  const client = await getPool().connect();

  try {
    await client.query("SELECT pg_advisory_lock($1, $2)", [MIGRATION_LOCK_KEY_1, MIGRATION_LOCK_KEY_2]);

    for (const statement of migrations) {
      await client.query(statement);
    }

    for (const seed of roleSeeds) {
      await client.query(
        `INSERT INTO roles (role_key, display_name, permissions)
         VALUES ($1, $2, $3::jsonb)
         ON CONFLICT (role_key)
         DO UPDATE SET display_name = EXCLUDED.display_name, permissions = EXCLUDED.permissions, updated_at = NOW()`,
        [seed.roleKey, seed.displayName, JSON.stringify(seed.permissions)]
      );
    }

    if (config.nodeEnv !== "production") {
      await client.query(
        `INSERT INTO users (
           username, display_name, email, password_hash, role, user_type
         )
         SELECT $1, $2, $3, $4, $5, $6
         WHERE NOT EXISTS (
           SELECT 1 FROM users WHERE username = $1
         )`,
        [
          "admin",
          "System Administrator",
          "admin@localhost",
          "bootstrapadminsalt:fb97e9cc26739c2d81cf40d87e71fc8b09eefe1cbf365946db567c46ba112acc17885558c85f9a5d6b16293714a30d5e091e85f9a5dbb88a7aea81ecf6c2eb41",
          "hr_admin",
          "application_user"
        ]
      );
    }
  } finally {
    try {
      await client.query("SELECT pg_advisory_unlock($1, $2)", [MIGRATION_LOCK_KEY_1, MIGRATION_LOCK_KEY_2]);
    } finally {
      client.release();
    }
  }
};

export const closeDb = async (): Promise<void> => {
  if (!pool) {
    return;
  }

  await pool.end();
  pool = undefined;
};
