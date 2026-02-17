import { exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";

type DpopAlg = "ES256";
type JsonObject = Record<string, unknown>;

type DpopProofInput = {
  url: string;
  method: string;
  accessToken?: string;
  nonce?: string;
};

export type DpopKeyMaterial = {
  alg: DpopAlg;
  publicJwk: JsonObject;
  privateJwk: JsonObject;
};

export type DpopFetchOptions = {
  accessToken?: string;
  nonce?: string;
  csrfToken?: string;
  includeCredentials?: boolean;
  maxNonceRetries?: number;
};

const DEFAULT_DPOP_ALG: DpopAlg = "ES256";
const CSRF_COOKIE_NAME = "csrf_token";

const normalizeHtu = (rawUrl: string): string => {
  const url = new URL(rawUrl, window.location.origin);
  url.search = "";
  url.hash = "";

  if ((url.protocol === "https:" && url.port === "443") || (url.protocol === "http:" && url.port === "80")) {
    url.port = "";
  }

  return url.toString();
};

const base64UrlEncode = (buffer: ArrayBuffer): string => {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const sha256Base64Url = async (value: string): Promise<string> => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64UrlEncode(digest);
};

const isNonceChallenge = (response: Response): boolean => {
  if (response.status !== 401) {
    return false;
  }

  const challenge = response.headers.get("www-authenticate") ?? "";
  return challenge.toLowerCase().includes("use_dpop_nonce");
};

const shouldAttachCsrfHeader = (method: string): boolean => {
  const normalized = method.toUpperCase();
  return !["GET", "HEAD", "OPTIONS", "TRACE"].includes(normalized);
};

export const getCookieValue = (name: string): string | undefined => {
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = document.cookie.match(new RegExp(`(?:^|; )${escapedName}=([^;]*)`));
  if (!match) {
    return undefined;
  }

  return decodeURIComponent(match[1]);
};

export const getCsrfToken = (): string | undefined => {
  return getCookieValue(CSRF_COOKIE_NAME);
};

export const createDpopKeyMaterial = async (): Promise<DpopKeyMaterial> => {
  const { publicKey, privateKey } = await generateKeyPair(DEFAULT_DPOP_ALG, {
    extractable: true
  });

  const publicJwk = (await exportJWK(publicKey)) as unknown as JsonObject;
  const privateJwk = (await exportJWK(privateKey)) as unknown as JsonObject;

  return {
    alg: DEFAULT_DPOP_ALG,
    publicJwk,
    privateJwk
  };
};

export const withDpopJwk = <T extends JsonObject>(payload: T, publicJwk: JsonObject): T & { dpop_jwk: JsonObject } => {
  return {
    ...payload,
    dpop_jwk: publicJwk
  };
};

export class DpopClient {
  private readonly alg: DpopAlg;
  private readonly privateKey: CryptoKey;
  private readonly publicJwk: JsonObject;
  private nonce?: string;

  private constructor(input: { alg: DpopAlg; privateKey: CryptoKey; publicJwk: JsonObject; nonce?: string }) {
    this.alg = input.alg;
    this.privateKey = input.privateKey;
    this.publicJwk = input.publicJwk;
    this.nonce = input.nonce;
  }

  static async create(): Promise<DpopClient> {
    const material = await createDpopKeyMaterial();
    const privateKey = (await importJWK(material.privateJwk as any, material.alg)) as CryptoKey;

    return new DpopClient({
      alg: material.alg,
      privateKey,
      publicJwk: material.publicJwk
    });
  }

  static async fromKeyMaterial(material: DpopKeyMaterial, nonce?: string): Promise<DpopClient> {
    const privateKey = (await importJWK(material.privateJwk as any, material.alg)) as CryptoKey;

    return new DpopClient({
      alg: material.alg,
      privateKey,
      publicJwk: material.publicJwk,
      nonce
    });
  }

  getPublicJwk(): JsonObject {
    return { ...this.publicJwk };
  }

  getNonce(): string | undefined {
    return this.nonce;
  }

  setNonce(nonce: string | undefined): void {
    this.nonce = nonce;
  }

  async exportKeyMaterial(): Promise<DpopKeyMaterial> {
    const privateJwk = (await exportJWK(this.privateKey)) as unknown as JsonObject;

    return {
      alg: this.alg,
      publicJwk: { ...this.publicJwk },
      privateJwk
    };
  }

  async createProof(input: DpopProofInput): Promise<string> {
    const htm = input.method.toUpperCase();
    const htu = normalizeHtu(input.url);

    const payload: Record<string, unknown> = {
      htm,
      htu,
      jti: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000)
    };

    if (input.accessToken) {
      payload.ath = await sha256Base64Url(input.accessToken);
    }

    if (input.nonce) {
      payload.nonce = input.nonce;
    }

    return new SignJWT(payload)
      .setProtectedHeader({
        alg: this.alg,
        typ: "dpop+jwt",
        jwk: this.publicJwk as any
      })
      .sign(this.privateKey);
  }

  async fetch(input: RequestInfo | URL, init: RequestInit = {}, options: DpopFetchOptions = {}): Promise<Response> {
    const baseRequest = new Request(input, init);
    const maxRetries = options.maxNonceRetries ?? 1;
    let nonce = options.nonce ?? this.nonce;

    for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
      const proof = await this.createProof({
        url: baseRequest.url,
        method: baseRequest.method,
        accessToken: options.accessToken,
        nonce
      });

      const headers = new Headers(baseRequest.headers);
      headers.set("DPoP", proof);

      if (options.accessToken) {
        headers.set("Authorization", `DPoP ${options.accessToken}`);
      }

      const csrfToken = options.csrfToken ?? getCsrfToken();
      if (csrfToken && shouldAttachCsrfHeader(baseRequest.method)) {
        headers.set("X-CSRF-Token", csrfToken);
      }

      const requestWithDpop = new Request(baseRequest, {
        headers,
        credentials: options.includeCredentials === false ? "same-origin" : "include"
      });

      const response = await fetch(requestWithDpop);

      const returnedNonce = response.headers.get("dpop-nonce") ?? response.headers.get("DPoP-Nonce") ?? undefined;
      if (returnedNonce) {
        this.nonce = returnedNonce;
      }

      if (!isNonceChallenge(response) || !returnedNonce || attempt >= maxRetries) {
        return response;
      }

      nonce = returnedNonce;
    }

    throw new Error("Unexpected DPoP retry flow state");
  }
}
