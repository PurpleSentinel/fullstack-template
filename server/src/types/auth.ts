export type AuthTokenClaims = {
  sub: string;
  username: string;
  role: string;
  sid: string;
  tv: number;
  jti: string;
  iat: number;
  exp: number;
  cnf?: {
    jkt: string;
  };
};

export type RequestUser = {
  id: number;
  username: string;
  role: string;
  sid: string;
  tokenVersion: number;
  permissions: string[];
  dpopJkt?: string;
};
