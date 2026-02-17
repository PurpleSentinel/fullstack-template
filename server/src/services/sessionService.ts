import { createHash, randomBytes, randomUUID } from "crypto";
import { config } from "../config";
import { get, run } from "../db";

export type SessionRow = {
  sid: string;
  session_family_id: string;
  user_id: number;
  refresh_token_hash: string;
  expires_at: string;
  revoked_at: string | null;
  dpop_jkt: string | null;
};

type CreateSessionInput = {
  userId: number;
  sourceIp?: string;
  userAgent?: string;
  dpopJkt?: string;
};

export type RefreshTokenInspection =
  | { status: "valid"; session: SessionRow }
  | { status: "reused"; session: SessionRow }
  | { status: "invalid" };

const hashToken = (rawToken: string): string => {
  return createHash("sha256").update(rawToken).digest("hex");
};

const buildRefreshToken = (sid: string): string => {
  return `${sid}.${randomBytes(48).toString("base64url")}`;
};

const parseSessionIdFromRefreshToken = (refreshToken: string): string | null => {
  const sid = refreshToken.split(".")[0];
  return sid || null;
};

const getSessionBySid = async (sid: string): Promise<SessionRow | null> => {
  return get<SessionRow>(
    `SELECT sid, session_family_id, user_id, refresh_token_hash, expires_at, revoked_at, dpop_jkt
     FROM auth_sessions
     WHERE sid = $1`,
    [sid]
  );
};

export const createSession = async (
  input: CreateSessionInput
): Promise<{ sid: string; refreshToken: string; refreshExpiresAt: string }> => {
  const sid = randomUUID();
  const sessionFamilyId = randomUUID();
  const refreshToken = buildRefreshToken(sid);
  const refreshTokenHash = hashToken(refreshToken);
  const refreshExpiresAt = new Date(Date.now() + config.auth.refreshTokenTtlSeconds * 1000).toISOString();

  await run(
    `INSERT INTO auth_sessions (
      sid, session_family_id, user_id, refresh_token_hash, dpop_jkt, user_agent, source_ip, expires_at
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      sid,
      sessionFamilyId,
      input.userId,
      refreshTokenHash,
      input.dpopJkt ?? null,
      input.userAgent ?? null,
      input.sourceIp ?? null,
      refreshExpiresAt
    ]
  );

  return { sid, refreshToken, refreshExpiresAt };
};

export const inspectRefreshToken = async (refreshToken: string): Promise<RefreshTokenInspection> => {
  const sid = parseSessionIdFromRefreshToken(refreshToken);
  if (!sid) {
    return { status: "invalid" };
  }

  const session = await getSessionBySid(sid);
  if (!session || session.revoked_at) {
    return { status: "invalid" };
  }

  if (new Date(session.expires_at).getTime() < Date.now()) {
    return { status: "invalid" };
  }

  if (session.refresh_token_hash !== hashToken(refreshToken)) {
    return { status: "reused", session };
  }

  return { status: "valid", session };
};

export const getSessionForRefresh = async (refreshToken: string): Promise<SessionRow | null> => {
  const inspected = await inspectRefreshToken(refreshToken);
  if (inspected.status !== "valid") {
    return null;
  }

  return inspected.session;
};

export const rotateRefreshToken = async (sid: string): Promise<{ refreshToken: string; refreshExpiresAt: string }> => {
  const refreshToken = buildRefreshToken(sid);
  const refreshTokenHash = hashToken(refreshToken);
  const refreshExpiresAt = new Date(Date.now() + config.auth.refreshTokenTtlSeconds * 1000).toISOString();

  await run(
    `UPDATE auth_sessions
     SET refresh_token_hash = $2,
         expires_at = $3,
         updated_at = NOW()
     WHERE sid = $1`,
    [sid, refreshTokenHash, refreshExpiresAt]
  );

  return { refreshToken, refreshExpiresAt };
};

export const revokeSession = async (sid: string): Promise<void> => {
  await run(
    `UPDATE auth_sessions
     SET revoked_at = NOW(), updated_at = NOW()
     WHERE sid = $1`,
    [sid]
  );
};

export const revokeSessionFamily = async (sessionFamilyId: string): Promise<void> => {
  await run(
    `UPDATE auth_sessions
     SET revoked_at = NOW(), updated_at = NOW()
     WHERE session_family_id = $1 AND revoked_at IS NULL`,
    [sessionFamilyId]
  );
};

export const revokeAllSessionsForUser = async (userId: number): Promise<void> => {
  await run(
    `UPDATE auth_sessions
     SET revoked_at = NOW(), updated_at = NOW()
     WHERE user_id = $1 AND revoked_at IS NULL`,
    [userId]
  );
};
