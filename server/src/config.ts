import dotenv from "dotenv";

dotenv.config();

const toInt = (value: string | undefined, fallback: number): number => {
  if (!value) {
    return fallback;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

const toBool = (value: string | undefined, fallback: boolean): boolean => {
  if (value === undefined) {
    return fallback;
  }

  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }

  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }

  return fallback;
};

const required = (name: string, fallback?: string): string => {
  const value = process.env[name] ?? fallback;
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }

  return value;
};

export const config = {
  nodeEnv: process.env.NODE_ENV ?? "development",
  serviceName: process.env.SERVICE_NAME ?? "unknown-service",
  servicePort: toInt(process.env.SERVICE_PORT, 3000),

  db: {
    host: required("PGHOST", "localhost"),
    port: toInt(process.env.PGPORT, 5432),
    user: required("PGUSER", "hr_admin"),
    password: required("PGPASSWORD", "hr_password"),
    database: required("PGDATABASE", "hr_system")
  },

  redis: {
    enabled: toBool(process.env.REDIS_ENABLED, true),
    host: required("REDIS_HOST", "redis"),
    port: toInt(process.env.REDIS_PORT, 6379),
    password: process.env.REDIS_PASSWORD || undefined,
    db: toInt(process.env.REDIS_DB, 0),
    keyPrefix: process.env.REDIS_KEY_PREFIX ?? "hr-system"
  },

  auth: {
    jwtSecret: required("JWT_SECRET", "unsafe-dev-secret"),
    jwtTtlSeconds: toInt(process.env.JWT_TTL_SECONDS, 900),
    refreshTokenTtlSeconds: toInt(process.env.REFRESH_TOKEN_TTL_SECONDS, 2592000),
    refreshWindowSeconds: toInt(process.env.JWT_REFRESH_WINDOW_SECONDS, 3600),
    maxFailedLogins: toInt(process.env.AUTH_MAX_FAILED_LOGINS, 5),
    autoUnlockMinutes: toInt(process.env.AUTH_AUTO_UNLOCK_MINUTES, 30)
  },

  mfa: {
    issuer: process.env.MFA_TOTP_ISSUER ?? "CorporateHR",
    periodSeconds: toInt(process.env.MFA_TOTP_PERIOD_SECONDS, 30),
    enrollTtlSeconds: toInt(process.env.MFA_ENROLL_TTL_SECONDS, 600),
    challengeTtlSeconds: toInt(process.env.MFA_CHALLENGE_TTL_SECONDS, 300)
  },

  dpop: {
    nonceTtlSeconds: toInt(process.env.DPOP_NONCE_TTL_SECONDS, 120),
    proofMaxAgeSeconds: toInt(process.env.DPOP_PROOF_MAX_AGE_SECONDS, 300)
  },

  pssMasterKey: required("PSS_MASTER_KEY", "unsafe-dev-master-key-32-bytes!!!!")
};

export type AppConfig = typeof config;
