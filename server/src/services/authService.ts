import { randomUUID, scryptSync, timingSafeEqual } from "crypto";
import jwt from "jsonwebtoken";
import { config } from "../config";
import { get, run } from "../db";
import { AuthTokenClaims } from "../types/auth";
import { computeJwkThumbprint } from "./dpopService";
import { createMfaChallenge, completeMfaChallenge } from "./mfaService";
import {
  createSession,
  inspectRefreshToken,
  RefreshTokenInspection,
  revokeAllSessionsForUser,
  revokeSession,
  revokeSessionFamily,
  rotateRefreshToken
} from "./sessionService";

type UserRow = {
  id: number;
  username: string;
  display_name: string;
  email: string | null;
  password_hash: string;
  is_active: boolean;
  role: string;
  user_type: string;
  token_version: number;
  failed_login_attempts: number;
  login_locked_until: string | null;
  mfa_enabled: boolean;
};

type RefreshableUserRow = {
  id: number;
  username: string;
  role: string;
  token_version: number;
  is_active: boolean;
};

type LoginContext = {
  sourceIp?: string;
  userAgent?: string;
  dpopJwk?: Record<string, unknown>;
};

type TokenBundle = {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  refreshExpiresAt: string;
};

export type LoginResult =
  | ({ status: "ok" } & TokenBundle)
  | { status: "invalid_credentials" }
  | { status: "disabled" }
  | { status: "locked"; retryAt: string }
  | { status: "mfa_required"; challengeId: string; expiresAt: string };

export type MfaLoginResult =
  | ({ status: "ok" } & TokenBundle)
  | { status: "invalid_mfa" };

export type RefreshSessionResult =
  | ({ status: "ok" } & TokenBundle)
  | { status: "invalid_refresh" }
  | { status: "refresh_reuse_detected" };

const hashPasswordRaw = (password: string, salt: string): Buffer => {
  return scryptSync(password, salt, 64);
};

export const hashPassword = (password: string): string => {
  const salt = randomUUID().replace(/-/g, "");
  const digest = hashPasswordRaw(password, salt);
  return `${salt}:${digest.toString("hex")}`;
};

export const verifyPassword = (password: string, stored: string): boolean => {
  const [salt, digestHex] = stored.split(":");
  if (!salt || !digestHex) {
    return false;
  }

  const expected = Buffer.from(digestHex, "hex");
  const actual = hashPasswordRaw(password, salt);
  if (expected.length !== actual.length) {
    return false;
  }

  return timingSafeEqual(expected, actual);
};

const issueAccessToken = (user: { id: number; username: string; role: string; tokenVersion: number }, sid: string, dpopJkt?: string): string => {
  const claims: Omit<AuthTokenClaims, "iat" | "exp"> = {
    sub: String(user.id),
    username: user.username,
    role: user.role,
    sid,
    tv: user.tokenVersion,
    jti: randomUUID()
  };

  if (dpopJkt) {
    claims.cnf = { jkt: dpopJkt };
  }

  return jwt.sign(claims, config.auth.jwtSecret, {
    algorithm: "HS256",
    expiresIn: config.auth.jwtTtlSeconds
  });
};

const fetchUserByUsername = async (username: string): Promise<UserRow | null> => {
  return get<UserRow>(
    `SELECT id, username, display_name, email, password_hash, is_active,
            role, user_type, token_version, failed_login_attempts,
            login_locked_until, mfa_enabled
     FROM users
     WHERE username = $1`,
    [username]
  );
};

const fetchUserById = async (id: number): Promise<RefreshableUserRow | null> => {
  return get<RefreshableUserRow>(
    `SELECT id, username, role, token_version, is_active
     FROM users
     WHERE id = $1`,
    [id]
  );
};

const recordFailedAttempt = async (user: UserRow): Promise<void> => {
  const attempts = user.failed_login_attempts + 1;
  const shouldLock = attempts >= config.auth.maxFailedLogins;
  const lockedUntil = shouldLock
    ? new Date(Date.now() + config.auth.autoUnlockMinutes * 60 * 1000).toISOString()
    : null;

  await run(
    `UPDATE users
     SET failed_login_attempts = $2,
         login_locked_until = $3,
         updated_at = NOW()
     WHERE id = $1`,
    [user.id, attempts, lockedUntil]
  );
};

const resetFailedAttemptState = async (userId: number): Promise<void> => {
  await run(
    `UPDATE users
     SET failed_login_attempts = 0,
         login_locked_until = NULL,
         last_login_at = NOW(),
         last_seen_at = NOW(),
         updated_at = NOW()
     WHERE id = $1`,
    [userId]
  );
};

const issueTokensForUser = async (
  user: RefreshableUserRow,
  context: LoginContext
): Promise<TokenBundle> => {
  const dpopJkt = context.dpopJwk ? computeJwkThumbprint(context.dpopJwk) : undefined;

  const session = await createSession({
    userId: user.id,
    sourceIp: context.sourceIp,
    userAgent: context.userAgent,
    dpopJkt
  });

  const accessToken = issueAccessToken(
    {
      id: user.id,
      username: user.username,
      role: user.role,
      tokenVersion: user.token_version
    },
    session.sid,
    dpopJkt
  );

  return {
    accessToken,
    refreshToken: session.refreshToken,
    expiresIn: config.auth.jwtTtlSeconds,
    refreshExpiresAt: session.refreshExpiresAt
  };
};

export const login = async (
  username: string,
  password: string,
  context: LoginContext
): Promise<LoginResult> => {
  const user = await fetchUserByUsername(username);
  if (!user) {
    return { status: "invalid_credentials" };
  }

  if (!user.is_active) {
    return { status: "disabled" };
  }

  if (user.login_locked_until && new Date(user.login_locked_until).getTime() > Date.now()) {
    return { status: "locked", retryAt: user.login_locked_until };
  }

  const validPassword = verifyPassword(password, user.password_hash);
  if (!validPassword) {
    await recordFailedAttempt(user);
    return { status: "invalid_credentials" };
  }

  await resetFailedAttemptState(user.id);

  if (user.mfa_enabled && user.user_type === "application_user") {
    const challenge = await createMfaChallenge(user.id);
    return {
      status: "mfa_required",
      challengeId: challenge.challengeId,
      expiresAt: challenge.expiresAt
    };
  }

  const refreshable = await fetchUserById(user.id);
  if (!refreshable || !refreshable.is_active) {
    return { status: "disabled" };
  }

  const tokens = await issueTokensForUser(refreshable, context);
  return { status: "ok", ...tokens };
};

export const completeMfaLogin = async (
  challengeId: string,
  code: string,
  context: LoginContext
): Promise<MfaLoginResult> => {
  const userId = await completeMfaChallenge(challengeId, code);
  if (!userId) {
    return { status: "invalid_mfa" };
  }

  const user = await fetchUserById(userId);
  if (!user || !user.is_active) {
    return { status: "invalid_mfa" };
  }

  const tokens = await issueTokensForUser(user, context);
  return { status: "ok", ...tokens };
};

export const handleRefreshTokenReuse = async (userId: number, sessionFamilyId: string): Promise<void> => {
  await revokeSessionFamily(sessionFamilyId);
  await run(
    `UPDATE users
     SET token_version = token_version + 1,
         updated_at = NOW()
     WHERE id = $1`,
    [userId]
  );
};

export const refreshSession = async (
  refreshToken: string,
  inspectionHint?: RefreshTokenInspection
): Promise<RefreshSessionResult> => {
  const inspection = inspectionHint ?? (await inspectRefreshToken(refreshToken));

  if (inspection.status === "invalid") {
    return { status: "invalid_refresh" };
  }

  if (inspection.status === "reused") {
    await handleRefreshTokenReuse(inspection.session.user_id, inspection.session.session_family_id);
    return { status: "refresh_reuse_detected" };
  }

  const session = inspection.session;
  const user = await fetchUserById(session.user_id);
  if (!user || !user.is_active) {
    return { status: "invalid_refresh" };
  }

  const rotated = await rotateRefreshToken(session.sid);
  const accessToken = issueAccessToken(
    {
      id: user.id,
      username: user.username,
      role: user.role,
      tokenVersion: user.token_version
    },
    session.sid,
    session.dpop_jkt ?? undefined
  );

  await run(
    `UPDATE users
     SET last_seen_at = NOW(),
         updated_at = NOW()
     WHERE id = $1`,
    [user.id]
  );

  return {
    status: "ok",
    accessToken,
    refreshToken: rotated.refreshToken,
    expiresIn: config.auth.jwtTtlSeconds,
    refreshExpiresAt: rotated.refreshExpiresAt
  };
};

export const logoutSession = async (sid: string): Promise<void> => {
  await revokeSession(sid);
};

export const forceLogoutUser = async (userId: number): Promise<void> => {
  await revokeAllSessionsForUser(userId);
  await run(
    `UPDATE users
     SET token_version = token_version + 1,
         updated_at = NOW()
     WHERE id = $1`,
    [userId]
  );
};
