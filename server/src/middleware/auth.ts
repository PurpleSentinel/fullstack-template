import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { config } from "../config";
import { get } from "../db";
import { buildExpectedHtu, issueDpopNonce, validateDpopProof } from "../services/dpopService";
import { AuthTokenClaims } from "../types/auth";

type UserRow = {
  id: number;
  username: string;
  role: string;
  token_version: number;
  is_active: boolean;
};

type SessionRow = {
  sid: string;
  user_id: number;
  revoked_at: string | null;
  expires_at: string;
  dpop_jkt: string | null;
};

type RoleRow = {
  permissions: string[];
};

type ParsedAuthorization = {
  scheme: "Bearer" | "DPoP";
  token: string;
};

const parseAuthorizationHeader = (headerValue: string | undefined): ParsedAuthorization | null => {
  if (!headerValue) {
    return null;
  }

  const [scheme, token] = headerValue.split(" ");
  if (!scheme || !token) {
    return null;
  }

  if (scheme !== "Bearer" && scheme !== "DPoP") {
    return null;
  }

  return {
    scheme,
    token
  };
};

const sendDpopNonceChallenge = (res: Response, nonce: string): void => {
  res.setHeader("DPoP-Nonce", nonce);
  res.setHeader("WWW-Authenticate", 'DPoP error="use_dpop_nonce"');
  res.status(401).json({ error: "DPoP nonce required" });
};

export const authenticateAccessToken = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const parsedAuth = parseAuthorizationHeader(req.header("authorization"));
    if (!parsedAuth) {
      res.status(401).json({ error: "Missing access token" });
      return;
    }

    const accessToken = parsedAuth.token;
    const decoded = jwt.verify(accessToken, config.auth.jwtSecret, {
      algorithms: ["HS256"]
    }) as AuthTokenClaims;

    if (!decoded.sid || typeof decoded.tv !== "number") {
      res.status(401).json({ error: "Malformed token" });
      return;
    }

    const user = await get<UserRow>(
      `SELECT id, username, role, token_version, is_active
       FROM users
       WHERE id = $1`,
      [Number(decoded.sub)]
    );

    if (!user || !user.is_active) {
      res.status(401).json({ error: "Invalid user context" });
      return;
    }

    if (user.token_version !== decoded.tv) {
      res.status(401).json({ error: "Token revoked" });
      return;
    }

    const session = await get<SessionRow>(
      `SELECT sid, user_id, revoked_at, expires_at, dpop_jkt
       FROM auth_sessions
       WHERE sid = $1`,
      [decoded.sid]
    );

    if (!session || session.user_id !== user.id || session.revoked_at) {
      res.status(401).json({ error: "Session revoked" });
      return;
    }

    if (new Date(session.expires_at).getTime() < Date.now()) {
      res.status(401).json({ error: "Session expired" });
      return;
    }

    const tokenJkt = decoded.cnf?.jkt;
    if (session.dpop_jkt && tokenJkt !== session.dpop_jkt) {
      res.status(401).json({ error: "DPoP binding mismatch" });
      return;
    }

    if (!session.dpop_jkt && tokenJkt) {
      res.status(401).json({ error: "DPoP binding mismatch" });
      return;
    }

    const expectedDpopJkt = session.dpop_jkt ?? tokenJkt;

    if (expectedDpopJkt) {
      if (parsedAuth.scheme !== "DPoP") {
        res.status(401).json({ error: "DPoP authorization scheme required" });
        return;
      }

      const dpopProof = req.header("dpop");
      if (!dpopProof) {
        const nonce = await issueDpopNonce();
        sendDpopNonceChallenge(res, nonce);
        return;
      }

      const dpopCheck = await validateDpopProof({
        proofJwt: dpopProof,
        method: req.method,
        htu: buildExpectedHtu(req),
        expectedJkt: expectedDpopJkt,
        accessToken,
        requireNonce: true
      });

      if (!dpopCheck.ok) {
        if (dpopCheck.reason === "nonce_required" || dpopCheck.reason === "nonce_invalid") {
          sendDpopNonceChallenge(res, dpopCheck.nonce);
          return;
        }

        if (dpopCheck.reason === "replay_detected") {
          res.status(401).json({ error: "DPoP proof replay detected" });
          return;
        }

        res.status(401).json({ error: "Invalid DPoP proof" });
        return;
      }
    } else if (parsedAuth.scheme === "DPoP") {
      res.status(401).json({ error: "Token is not DPoP-bound" });
      return;
    }

    const role = await get<RoleRow>(
      `SELECT permissions
       FROM roles
       WHERE role_key = $1`,
      [user.role]
    );

    req.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      sid: decoded.sid,
      tokenVersion: decoded.tv,
      permissions: role?.permissions ?? [],
      dpopJkt: tokenJkt
    };

    next();
  } catch {
    res.status(401).json({ error: "Unauthorized" });
  }
};

export const requirePermission = (permission: string) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    if (!req.user.permissions.includes(permission)) {
      res.status(403).json({ error: "Forbidden" });
      return;
    }

    next();
  };
};
