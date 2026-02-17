import { randomUUID } from "crypto";
import { authenticator } from "otplib";
import QRCode from "qrcode";
import { config } from "../config";
import { get, run } from "../db";
import { decrypt, encrypt } from "../utils/secrets";

authenticator.options = {
  step: config.mfa.periodSeconds,
  window: 1
};

type UserMfaRow = {
  id: number;
  username: string;
  mfa_enabled: boolean;
  mfa_totp_secret_cipher: string | null;
  mfa_pending_secret_cipher: string | null;
  mfa_pending_created_at: string | null;
  mfa_last_used_step: number | null;
};

type ChallengeRow = {
  challenge_id: string;
  user_id: number;
  expires_at: string;
  consumed_at: string | null;
};

const currentStep = (): number => Math.floor(Date.now() / 1000 / config.mfa.periodSeconds);

export const startMfaEnrollment = async (
  userId: number,
  username: string
): Promise<{ otpAuthUri: string; qrDataUrl: string; manualKey: string; expiresAt: string }> => {
  const secret = authenticator.generateSecret();
  const otpAuthUri = authenticator.keyuri(username, config.mfa.issuer, secret);
  const qrDataUrl = await QRCode.toDataURL(otpAuthUri);
  const expiresAt = new Date(Date.now() + config.mfa.enrollTtlSeconds * 1000).toISOString();

  await run(
    `UPDATE users
     SET mfa_pending_secret_cipher = $2,
         mfa_pending_created_at = NOW(),
         updated_at = NOW()
     WHERE id = $1`,
    [userId, encrypt(secret)]
  );

  return {
    otpAuthUri,
    qrDataUrl,
    manualKey: `${secret.slice(0, 4)}****${secret.slice(-4)}`,
    expiresAt
  };
};

export const verifyMfaEnrollment = async (userId: number, code: string): Promise<boolean> => {
  const user = await get<UserMfaRow>(
    `SELECT id, username, mfa_enabled, mfa_totp_secret_cipher,
            mfa_pending_secret_cipher, mfa_pending_created_at, mfa_last_used_step
     FROM users
     WHERE id = $1`,
    [userId]
  );

  if (!user?.mfa_pending_secret_cipher || !user.mfa_pending_created_at) {
    return false;
  }

  const pendingCreatedAt = new Date(user.mfa_pending_created_at).getTime();
  if (pendingCreatedAt + config.mfa.enrollTtlSeconds * 1000 < Date.now()) {
    return false;
  }

  const secret = decrypt(user.mfa_pending_secret_cipher);
  if (!authenticator.check(code, secret)) {
    return false;
  }

  await run(
    `UPDATE users
     SET mfa_enabled = TRUE,
         mfa_totp_secret_cipher = mfa_pending_secret_cipher,
         mfa_pending_secret_cipher = NULL,
         mfa_pending_created_at = NULL,
         updated_at = NOW()
     WHERE id = $1`,
    [userId]
  );

  return true;
};

export const createMfaChallenge = async (userId: number): Promise<{ challengeId: string; expiresAt: string }> => {
  const challengeId = randomUUID();
  const expiresAt = new Date(Date.now() + config.mfa.challengeTtlSeconds * 1000).toISOString();

  await run(
    `INSERT INTO auth_mfa_challenges (challenge_id, user_id, expires_at)
     VALUES ($1, $2, $3)`,
    [challengeId, userId, expiresAt]
  );

  return { challengeId, expiresAt };
};

export const completeMfaChallenge = async (challengeId: string, code: string): Promise<number | null> => {
  const challenge = await get<ChallengeRow>(
    `SELECT challenge_id, user_id, expires_at, consumed_at
     FROM auth_mfa_challenges
     WHERE challenge_id = $1`,
    [challengeId]
  );

  if (!challenge || challenge.consumed_at || new Date(challenge.expires_at).getTime() < Date.now()) {
    return null;
  }

  const user = await get<UserMfaRow>(
    `SELECT id, username, mfa_enabled, mfa_totp_secret_cipher,
            mfa_pending_secret_cipher, mfa_pending_created_at, mfa_last_used_step
     FROM users
     WHERE id = $1`,
    [challenge.user_id]
  );

  if (!user?.mfa_enabled || !user.mfa_totp_secret_cipher) {
    return null;
  }

  const secret = decrypt(user.mfa_totp_secret_cipher);
  if (!authenticator.check(code, secret)) {
    return null;
  }

  const step = currentStep();
  if (user.mfa_last_used_step && step <= user.mfa_last_used_step) {
    return null;
  }

  await run(
    `UPDATE auth_mfa_challenges
     SET consumed_at = NOW()
     WHERE challenge_id = $1`,
    [challengeId]
  );

  await run(
    `UPDATE users
     SET mfa_last_used_step = $2,
         updated_at = NOW()
     WHERE id = $1`,
    [user.id, step]
  );

  return user.id;
};
