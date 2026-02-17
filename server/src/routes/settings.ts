import { Router } from "express";
import { authenticateAccessToken, requirePermission } from "../middleware/auth";
import { config } from "../config";

export const settingsRouter = Router();

settingsRouter.get(
  "/api/settings/security",
  authenticateAccessToken,
  requirePermission("settings:read"),
  (_req, res) => {
    res.status(200).json({
      auth: {
        jwt_ttl_seconds: config.auth.jwtTtlSeconds,
        refresh_ttl_seconds: config.auth.refreshTokenTtlSeconds,
        refresh_window_seconds: config.auth.refreshWindowSeconds,
        max_failed_logins: config.auth.maxFailedLogins,
        auto_unlock_minutes: config.auth.autoUnlockMinutes
      },
      mfa: {
        issuer: config.mfa.issuer,
        period_seconds: config.mfa.periodSeconds,
        enroll_ttl_seconds: config.mfa.enrollTtlSeconds,
        challenge_ttl_seconds: config.mfa.challengeTtlSeconds
      },
      dpop: {
        nonce_ttl_seconds: config.dpop.nonceTtlSeconds,
        proof_max_age_seconds: config.dpop.proofMaxAgeSeconds
      }
    });
  }
);

settingsRouter.patch(
  "/api/settings/security",
  authenticateAccessToken,
  requirePermission("settings:write"),
  (_req, res) => {
    res.status(501).json({
      error: "Runtime settings mutation is not implemented in this template"
    });
  }
);
