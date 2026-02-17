import { Request, Response, Router } from "express";
import { z } from "zod";
import { config } from "../config";
import { authenticateAccessToken, requirePermission } from "../middleware/auth";
import { createRedisRateLimiter } from "../middleware/rateLimit";
import {
  completeMfaLogin,
  forceLogoutUser,
  handleRefreshTokenReuse,
  login,
  logoutSession,
  refreshSession
} from "../services/authService";
import { writeAuditLog } from "../services/auditService";
import { buildExpectedHtu, issueDpopNonce, validateDpopProof } from "../services/dpopService";
import { startMfaEnrollment, verifyMfaEnrollment } from "../services/mfaService";
import { inspectRefreshToken } from "../services/sessionService";
import {
  clearCsrfCookie,
  clearRefreshTokenCookie,
  csrfTokensMatch,
  getCookie,
  getCsrfCookieName,
  getRefreshCookieName,
  issueCsrfToken,
  setCsrfCookie,
  setRefreshTokenCookie
} from "../utils/httpCookies";

const loginSchema = z.object({
  username: z.string().min(1),
  password: z.string().min(8),
  dpop_jwk: z.record(z.unknown()).optional()
});

const mfaCompleteSchema = z.object({
  challenge_id: z.string().uuid(),
  code: z.string().regex(/^\d{6}$/),
  dpop_jwk: z.record(z.unknown()).optional()
});

const mfaVerifySchema = z.object({
  code: z.string().regex(/^\d{6}$/)
});

const noStore = (res: Response): void => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
};

const sendDpopNonceChallenge = (res: Response, nonce: string): void => {
  res.setHeader("DPoP-Nonce", nonce);
  res.setHeader("WWW-Authenticate", 'DPoP error="use_dpop_nonce"');
};

const getClientIpKey = (req: Request): string => {
  return req.ip || req.socket.remoteAddress || "unknown";
};

const loginIpLimiter = createRedisRateLimiter({
  keyPrefix: `${config.redis.keyPrefix}:rl:auth:login:ip`,
  windowSeconds: 15 * 60,
  maxRequests: 30,
  message: "Too many login attempts from this IP",
  keyBuilder: (req) => getClientIpKey(req)
});

const loginAccountLimiter = createRedisRateLimiter({
  keyPrefix: `${config.redis.keyPrefix}:rl:auth:login:account`,
  windowSeconds: 15 * 60,
  maxRequests: 12,
  message: "Too many login attempts for this account",
  keyBuilder: (req) => {
    const username = typeof req.body?.username === "string" ? req.body.username.trim().toLowerCase() : "";
    return username || null;
  }
});

const refreshIpLimiter = createRedisRateLimiter({
  keyPrefix: `${config.redis.keyPrefix}:rl:auth:refresh:ip`,
  windowSeconds: 5 * 60,
  maxRequests: 40,
  message: "Too many refresh attempts from this IP",
  keyBuilder: (req) => getClientIpKey(req)
});

const mfaCompleteLimiter = createRedisRateLimiter({
  keyPrefix: `${config.redis.keyPrefix}:rl:auth:mfa:complete:ip`,
  windowSeconds: 10 * 60,
  maxRequests: 20,
  message: "Too many MFA completion attempts",
  keyBuilder: (req) => getClientIpKey(req)
});

const mfaVerifyLimiter = createRedisRateLimiter({
  keyPrefix: `${config.redis.keyPrefix}:rl:auth:mfa:verify:ip`,
  windowSeconds: 10 * 60,
  maxRequests: 30,
  message: "Too many MFA verification attempts",
  keyBuilder: (req) => getClientIpKey(req)
});

const setAuthCookies = (res: Response, refreshToken: string): string => {
  const csrfToken = issueCsrfToken();

  setRefreshTokenCookie(res, refreshToken, config.auth.refreshTokenTtlSeconds);
  setCsrfCookie(res, csrfToken, config.auth.refreshTokenTtlSeconds);

  return csrfToken;
};

const clearAuthCookies = (res: Response): void => {
  clearRefreshTokenCookie(res);
  clearCsrfCookie(res);
};

export const authRouter = Router();

authRouter.post("/api/auth/login", loginIpLimiter, loginAccountLimiter, async (req, res, next) => {
  try {
    const payload = loginSchema.parse(req.body);

    const result = await login(payload.username, payload.password, {
      sourceIp: req.ip,
      userAgent: req.header("user-agent") ?? undefined,
      dpopJwk: payload.dpop_jwk
    });

    if (result.status === "invalid_credentials") {
      await writeAuditLog({
        action: "auth.login.failed",
        resource: "session",
        statusCode: 401,
        req,
        metadata: { username: payload.username }
      });

      res.status(401).json({ error: "Invalid username or password" });
      return;
    }

    if (result.status === "disabled") {
      await writeAuditLog({
        action: "auth.login.disabled",
        resource: "session",
        statusCode: 403,
        req,
        metadata: { username: payload.username }
      });

      res.status(403).json({ error: "Account disabled" });
      return;
    }

    if (result.status === "locked") {
      await writeAuditLog({
        action: "auth.login.locked",
        resource: "session",
        statusCode: 423,
        req,
        metadata: { username: payload.username, retryAt: result.retryAt }
      });

      res.status(423).json({ error: "Account temporarily locked", retry_at: result.retryAt });
      return;
    }

    if (result.status === "mfa_required") {
      noStore(res);
      res.status(200).json({
        mfa_required: true,
        challenge_id: result.challengeId,
        expires_at: result.expiresAt
      });
      return;
    }

    const csrfToken = setAuthCookies(res, result.refreshToken);
    noStore(res);

    await writeAuditLog({
      action: "auth.login.success",
      resource: "session",
      statusCode: 200,
      req,
      metadata: { username: payload.username }
    });

    res.status(200).json({
      access_token: result.accessToken,
      token_type: "Bearer",
      expires_in: result.expiresIn,
      refresh_expires_at: result.refreshExpiresAt,
      csrf_token: csrfToken
    });
  } catch (error) {
    next(error);
  }
});

authRouter.post("/api/auth/refresh", refreshIpLimiter, async (req, res, next) => {
  try {
    const refreshToken = getCookie(req, getRefreshCookieName());

    if (!refreshToken) {
      clearAuthCookies(res);
      await writeAuditLog({
        action: "auth.refresh.failed",
        resource: "session",
        statusCode: 401,
        req,
        metadata: { reason: "missing_refresh_cookie" }
      });
      res.status(401).json({ error: "Missing refresh cookie" });
      return;
    }

    const csrfCookie = getCookie(req, getCsrfCookieName());
    const csrfHeader = req.header("x-csrf-token") ?? undefined;

    if (!csrfTokensMatch(csrfCookie, csrfHeader)) {
      res.status(403).json({ error: "CSRF token validation failed" });
      return;
    }

    const inspection = await inspectRefreshToken(refreshToken);

    if (inspection.status === "invalid") {
      clearAuthCookies(res);
      await writeAuditLog({
        action: "auth.refresh.failed",
        resource: "session",
        statusCode: 401,
        req,
        metadata: { reason: "invalid_refresh" }
      });
      res.status(401).json({ error: "Invalid refresh token" });
      return;
    }

    if (inspection.status === "reused") {
      await handleRefreshTokenReuse(inspection.session.user_id, inspection.session.session_family_id);
      clearAuthCookies(res);

      await writeAuditLog({
        action: "auth.refresh.reuse_detected",
        resource: "session",
        statusCode: 401,
        req,
        metadata: {
          sid: inspection.session.sid,
          session_family_id: inspection.session.session_family_id,
          user_id: inspection.session.user_id
        }
      });

      res.status(401).json({ error: "Refresh token reuse detected; session family revoked" });
      return;
    }

    if (inspection.session.dpop_jkt) {
      const dpopProof = req.header("dpop");
      if (!dpopProof) {
        const nonce = await issueDpopNonce();
        sendDpopNonceChallenge(res, nonce);
        res.status(401).json({ error: "DPoP proof required for refresh" });
        return;
      }

      const dpopCheck = await validateDpopProof({
        proofJwt: dpopProof,
        method: req.method,
        htu: buildExpectedHtu(req),
        expectedJkt: inspection.session.dpop_jkt,
        requireNonce: true
      });

      if (!dpopCheck.ok) {
        if (dpopCheck.reason === "nonce_required" || dpopCheck.reason === "nonce_invalid") {
          sendDpopNonceChallenge(res, dpopCheck.nonce);
          res.status(401).json({ error: "DPoP nonce required for refresh" });
          return;
        }

        if (dpopCheck.reason === "replay_detected") {
          res.status(401).json({ error: "DPoP proof replay detected" });
          return;
        }

        res.status(401).json({ error: "Invalid DPoP proof" });
        return;
      }
    }

    const result = await refreshSession(refreshToken, inspection);

    if (result.status === "refresh_reuse_detected") {
      clearAuthCookies(res);
      await writeAuditLog({
        action: "auth.refresh.reuse_detected",
        resource: "session",
        statusCode: 401,
        req,
        metadata: { reason: "reuse_detected_during_rotation" }
      });
      res.status(401).json({ error: "Refresh token reuse detected; session family revoked" });
      return;
    }

    if (result.status !== "ok") {
      clearAuthCookies(res);
      await writeAuditLog({
        action: "auth.refresh.failed",
        resource: "session",
        statusCode: 401,
        req,
        metadata: { reason: "invalid_after_validation" }
      });
      res.status(401).json({ error: "Invalid refresh token" });
      return;
    }

    const csrfToken = setAuthCookies(res, result.refreshToken);
    noStore(res);

    await writeAuditLog({
      action: "auth.refresh.success",
      resource: "session",
      statusCode: 200,
      req
    });

    res.status(200).json({
      access_token: result.accessToken,
      token_type: "Bearer",
      expires_in: result.expiresIn,
      refresh_expires_at: result.refreshExpiresAt,
      csrf_token: csrfToken
    });
  } catch (error) {
    next(error);
  }
});

authRouter.post("/api/auth/logout", authenticateAccessToken, async (req, res, next) => {
  try {
    if (!req.user) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    await logoutSession(req.user.sid);
    clearAuthCookies(res);

    await writeAuditLog({
      action: "auth.logout",
      resource: "session",
      statusCode: 200,
      req,
      actor: {
        userId: req.user.id,
        username: req.user.username,
        role: req.user.role
      }
    });

    noStore(res);
    res.status(200).json({ status: "ok" });
  } catch (error) {
    next(error);
  }
});

authRouter.post(
  "/api/auth/users/:userId/force-logout",
  authenticateAccessToken,
  requirePermission("sessions:revoke"),
  async (req, res, next) => {
    try {
      const userId = Number.parseInt(req.params.userId ?? "", 10);
      if (!Number.isFinite(userId)) {
        res.status(400).json({ error: "Invalid user id" });
        return;
      }

      await forceLogoutUser(userId);

      await writeAuditLog({
        action: "auth.force_logout",
        resource: "user",
        statusCode: 200,
        req,
        actor: {
          userId: req.user?.id,
          username: req.user?.username,
          role: req.user?.role
        },
        metadata: { target_user_id: userId }
      });

      res.status(200).json({ status: "ok" });
    } catch (error) {
      next(error);
    }
  }
);

authRouter.post("/api/auth/mfa/complete", mfaCompleteLimiter, async (req, res, next) => {
  try {
    const payload = mfaCompleteSchema.parse(req.body);
    const result = await completeMfaLogin(payload.challenge_id, payload.code, {
      sourceIp: req.ip,
      userAgent: req.header("user-agent") ?? undefined,
      dpopJwk: payload.dpop_jwk
    });

    if (result.status !== "ok") {
      res.status(401).json({ error: "Invalid MFA challenge or code" });
      return;
    }

    const csrfToken = setAuthCookies(res, result.refreshToken);
    noStore(res);
    res.status(200).json({
      access_token: result.accessToken,
      token_type: "Bearer",
      expires_in: result.expiresIn,
      refresh_expires_at: result.refreshExpiresAt,
      csrf_token: csrfToken
    });
  } catch (error) {
    next(error);
  }
});

authRouter.post("/api/auth/mfa/enroll/start", mfaVerifyLimiter, authenticateAccessToken, async (req, res, next) => {
  try {
    if (!req.user) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const enrollment = await startMfaEnrollment(req.user.id, req.user.username);
    noStore(res);
    res.status(200).json({
      otp_auth_uri: enrollment.otpAuthUri,
      qr_data_url: enrollment.qrDataUrl,
      manual_key: enrollment.manualKey,
      expires_at: enrollment.expiresAt
    });
  } catch (error) {
    next(error);
  }
});

authRouter.post("/api/auth/mfa/enroll/verify", mfaVerifyLimiter, authenticateAccessToken, async (req, res, next) => {
  try {
    if (!req.user) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const payload = mfaVerifySchema.parse(req.body);
    const verified = await verifyMfaEnrollment(req.user.id, payload.code);

    if (!verified) {
      res.status(400).json({ error: "MFA verification failed" });
      return;
    }

    res.status(200).json({ status: "ok" });
  } catch (error) {
    next(error);
  }
});
