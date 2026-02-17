import { randomBytes, timingSafeEqual } from "crypto";
import { Request, Response } from "express";
import { parse, serialize } from "cookie";

const REFRESH_COOKIE_NAME = "refresh_token";
const CSRF_COOKIE_NAME = "csrf_token";

const appendSetCookie = (res: Response, cookieValue: string): void => {
  const existing = res.getHeader("Set-Cookie");

  if (!existing) {
    res.setHeader("Set-Cookie", cookieValue);
    return;
  }

  if (Array.isArray(existing)) {
    res.setHeader("Set-Cookie", [...existing, cookieValue]);
    return;
  }

  res.setHeader("Set-Cookie", [String(existing), cookieValue]);
};

export const parseRequestCookies = (req: Request): Record<string, string> => {
  return parse(req.headers.cookie ?? "");
};

export const getCookie = (req: Request, name: string): string | undefined => {
  return parseRequestCookies(req)[name];
};

export const issueCsrfToken = (): string => {
  return randomBytes(32).toString("base64url");
};

export const csrfTokensMatch = (cookieToken: string | undefined, headerToken: string | undefined): boolean => {
  if (!cookieToken || !headerToken) {
    return false;
  }

  const cookieBytes = Buffer.from(cookieToken);
  const headerBytes = Buffer.from(headerToken);

  if (cookieBytes.length !== headerBytes.length) {
    return false;
  }

  return timingSafeEqual(cookieBytes, headerBytes);
};

export const setRefreshTokenCookie = (res: Response, refreshToken: string, ttlSeconds: number): void => {
  appendSetCookie(
    res,
    serialize(REFRESH_COOKIE_NAME, refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/api/auth",
      maxAge: ttlSeconds
    })
  );
};

export const clearRefreshTokenCookie = (res: Response): void => {
  appendSetCookie(
    res,
    serialize(REFRESH_COOKIE_NAME, "", {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/api/auth",
      maxAge: 0,
      expires: new Date(0)
    })
  );
};

export const setCsrfCookie = (res: Response, csrfToken: string, ttlSeconds: number): void => {
  appendSetCookie(
    res,
    serialize(CSRF_COOKIE_NAME, csrfToken, {
      httpOnly: false,
      secure: true,
      sameSite: "strict",
      path: "/",
      maxAge: ttlSeconds
    })
  );
};

export const clearCsrfCookie = (res: Response): void => {
  appendSetCookie(
    res,
    serialize(CSRF_COOKIE_NAME, "", {
      httpOnly: false,
      secure: true,
      sameSite: "strict",
      path: "/",
      maxAge: 0,
      expires: new Date(0)
    })
  );
};

export const getCsrfCookieName = (): string => CSRF_COOKIE_NAME;
export const getRefreshCookieName = (): string => REFRESH_COOKIE_NAME;
