import { createHash, createPublicKey, randomBytes } from "crypto";
import { Request } from "express";
import jwt, { JwtHeader, JwtPayload } from "jsonwebtoken";
import { config } from "../config";
import { run } from "../db";

type JsonLike = Record<string, unknown>;

type DpopProofPayload = JwtPayload & {
  htm?: string;
  htu?: string;
  jti?: string;
  iat?: number;
  ath?: string;
  nonce?: string;
};

type ParsedProof = {
  payload: DpopProofPayload;
  jkt: string;
};

type ValidateDpopProofInput = {
  proofJwt: string;
  method: string;
  htu: string;
  expectedJkt: string;
  accessToken?: string;
  requireNonce: boolean;
};

export type ValidateDpopProofResult =
  | { ok: true; jkt: string }
  | { ok: false; reason: "nonce_required" | "nonce_invalid"; nonce: string }
  | { ok: false; reason: "invalid_proof" | "replay_detected" | "jkt_mismatch" };

const DPOP_ALLOWED_ALGORITHMS: Set<jwt.Algorithm> = new Set([
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512"
]);

const PRIVATE_JWK_FIELDS = new Set(["d", "p", "q", "dp", "dq", "qi", "oth", "k"]);

const canonicalize = (input: JsonLike): string => {
  const sortedKeys = Object.keys(input).sort();
  const output: JsonLike = {};

  for (const key of sortedKeys) {
    output[key] = input[key];
  }

  return JSON.stringify(output);
};

const getThumbprintMaterial = (jwk: JsonLike): JsonLike => {
  const kty = jwk.kty;
  if (typeof kty !== "string") {
    throw new Error("Invalid JWK: missing kty");
  }

  switch (kty) {
    case "RSA": {
      const n = jwk.n;
      const e = jwk.e;
      if (typeof n !== "string" || typeof e !== "string") {
        throw new Error("Invalid RSA JWK");
      }

      return { e, kty, n };
    }
    case "EC": {
      const crv = jwk.crv;
      const x = jwk.x;
      const y = jwk.y;
      if (typeof crv !== "string" || typeof x !== "string" || typeof y !== "string") {
        throw new Error("Invalid EC JWK");
      }

      return { crv, kty, x, y };
    }
    case "OKP": {
      const crv = jwk.crv;
      const x = jwk.x;
      if (typeof crv !== "string" || typeof x !== "string") {
        throw new Error("Invalid OKP JWK");
      }

      return { crv, kty, x };
    }
    default:
      throw new Error("Unsupported JWK kty");
  }
};

const normalizeHtu = (rawUri: string): string | null => {
  try {
    const url = new URL(rawUri);
    url.search = "";
    url.hash = "";

    if ((url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80")) {
      url.port = "";
    }

    return url.toString();
  } catch {
    return null;
  }
};

const hashForAth = (value: string): string => {
  return createHash("sha256").update(value).digest("base64url");
};

const nowSeconds = (): number => Math.floor(Date.now() / 1000);

const cleanupExpiredArtifacts = async (): Promise<void> => {
  await run(`DELETE FROM dpop_nonces WHERE expires_at <= NOW()`);
  await run(`DELETE FROM dpop_replay_cache WHERE expires_at <= NOW()`);
};

const consumeNonce = async (nonce: string): Promise<boolean> => {
  const consumed = await run(
    `DELETE FROM dpop_nonces
     WHERE nonce = $1
       AND expires_at > NOW()`,
    [nonce]
  );

  return consumed === 1;
};

const registerProofJti = async (jti: string, htu: string, htm: string, iat: number): Promise<boolean> => {
  const expiryEpoch = Math.max(iat, nowSeconds()) + config.dpop.proofMaxAgeSeconds;
  const expiresAt = new Date(expiryEpoch * 1000).toISOString();

  const inserted = await run(
    `INSERT INTO dpop_replay_cache (jti, htu, htm, expires_at)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT DO NOTHING`,
    [jti, htu, htm, expiresAt]
  );

  return inserted === 1;
};

const parseAndVerifyProof = (proofJwt: string): ParsedProof | null => {
  const decoded = jwt.decode(proofJwt, { complete: true });
  if (!decoded || typeof decoded !== "object") {
    return null;
  }

  const header = decoded.header as JwtHeader & { jwk?: JsonLike };
  const typ = typeof header.typ === "string" ? header.typ.toLowerCase() : "";
  if (typ !== "dpop+jwt") {
    return null;
  }

  const rawAlg = header.alg;
  if (!rawAlg || !DPOP_ALLOWED_ALGORITHMS.has(rawAlg as jwt.Algorithm)) {
    return null;
  }

  const algorithm = rawAlg as jwt.Algorithm;
  const jwk = header.jwk;
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) {
    return null;
  }

  for (const privateField of PRIVATE_JWK_FIELDS) {
    if (privateField in jwk) {
      return null;
    }
  }

  try {
    const key = createPublicKey({ key: jwk as any, format: "jwk" });

    const verified = jwt.verify(proofJwt, key, {
      algorithms: [algorithm],
      clockTolerance: 5,
      ignoreExpiration: false
    });

    if (!verified || typeof verified !== "object") {
      return null;
    }

    const payload = verified as DpopProofPayload;
    return {
      payload,
      jkt: computeJwkThumbprint(jwk)
    };
  } catch {
    return null;
  }
};

export const computeJwkThumbprint = (jwk: JsonLike): string => {
  return createHash("sha256").update(canonicalize(getThumbprintMaterial(jwk))).digest("base64url");
};

export const generateDpopNonce = (): string => {
  return randomBytes(16).toString("base64url");
};

export const issueDpopNonce = async (): Promise<string> => {
  const nonce = generateDpopNonce();
  const expiresAt = new Date(Date.now() + config.dpop.nonceTtlSeconds * 1000).toISOString();

  await run(
    `INSERT INTO dpop_nonces (nonce, expires_at)
     VALUES ($1, $2)
     ON CONFLICT (nonce)
     DO UPDATE SET expires_at = EXCLUDED.expires_at`,
    [nonce, expiresAt]
  );

  return nonce;
};

export const buildExpectedHtu = (req: Request): string => {
  const forwardedProto = req.header("x-forwarded-proto")?.split(",")[0]?.trim();
  const scheme = forwardedProto || req.protocol || "https";
  const host = req.header("x-forwarded-host") ?? req.header("host") ?? "localhost";
  const path = req.originalUrl.split("?")[0] || "/";

  const uri = `${scheme}://${host}${path}`;
  return normalizeHtu(uri) ?? uri;
};

export const validateDpopProof = async (
  input: ValidateDpopProofInput
): Promise<ValidateDpopProofResult> => {
  await cleanupExpiredArtifacts();

  const parsed = parseAndVerifyProof(input.proofJwt);
  if (!parsed) {
    return { ok: false, reason: "invalid_proof" };
  }

  if (parsed.jkt !== input.expectedJkt) {
    return { ok: false, reason: "jkt_mismatch" };
  }

  const { payload } = parsed;
  if (
    typeof payload.htm !== "string" ||
    typeof payload.htu !== "string" ||
    typeof payload.jti !== "string" ||
    typeof payload.iat !== "number"
  ) {
    return { ok: false, reason: "invalid_proof" };
  }

  const normalizedProofHtu = normalizeHtu(payload.htu);
  const normalizedExpectedHtu = normalizeHtu(input.htu);
  const normalizedProofMethod = payload.htm.toUpperCase();
  const normalizedExpectedMethod = input.method.toUpperCase();

  if (!normalizedProofHtu || !normalizedExpectedHtu || normalizedProofHtu !== normalizedExpectedHtu) {
    return { ok: false, reason: "invalid_proof" };
  }

  if (normalizedProofMethod !== normalizedExpectedMethod) {
    return { ok: false, reason: "invalid_proof" };
  }

  const now = nowSeconds();
  if (payload.iat < now - config.dpop.proofMaxAgeSeconds || payload.iat > now + 60) {
    return { ok: false, reason: "invalid_proof" };
  }

  if (input.accessToken) {
    if (typeof payload.ath !== "string" || payload.ath !== hashForAth(input.accessToken)) {
      return { ok: false, reason: "invalid_proof" };
    }
  }

  if (input.requireNonce) {
    if (typeof payload.nonce !== "string" || payload.nonce.length < 8) {
      return { ok: false, reason: "nonce_required", nonce: await issueDpopNonce() };
    }

    const validNonce = await consumeNonce(payload.nonce);
    if (!validNonce) {
      return { ok: false, reason: "nonce_invalid", nonce: await issueDpopNonce() };
    }
  }

  const replaySafe = await registerProofJti(
    payload.jti,
    normalizedProofHtu,
    normalizedProofMethod,
    payload.iat
  );

  if (!replaySafe) {
    return { ok: false, reason: "replay_detected" };
  }

  return { ok: true, jkt: parsed.jkt };
};

export const isDpopBound = (jkt: string | undefined): boolean => {
  return Boolean(jkt && jkt.length > 10);
};
