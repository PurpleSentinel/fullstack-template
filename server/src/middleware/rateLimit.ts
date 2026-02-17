import { NextFunction, Request, Response } from "express";
import { getRedisClient } from "../redis";

type RateLimiterOptions = {
  keyPrefix: string;
  windowSeconds: number;
  maxRequests: number;
  message: string;
  keyBuilder: (req: Request) => string | null;
};

const normalizeKeySegment = (value: string): string => {
  return value.trim().toLowerCase().replace(/[^a-z0-9:._-]/g, "_").slice(0, 200);
};

export const createRedisRateLimiter = (options: RateLimiterOptions) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const redis = await getRedisClient();
      if (!redis) {
        next();
        return;
      }

      const rawKey = options.keyBuilder(req);
      if (!rawKey) {
        next();
        return;
      }

      const key = `${options.keyPrefix}:${normalizeKeySegment(rawKey)}`;
      const count = await redis.incr(key);

      if (count === 1) {
        await redis.expire(key, options.windowSeconds);
      }

      const remaining = Math.max(options.maxRequests - count, 0);
      res.setHeader("X-RateLimit-Limit", String(options.maxRequests));
      res.setHeader("X-RateLimit-Remaining", String(remaining));

      if (count > options.maxRequests) {
        res.setHeader("Retry-After", String(options.windowSeconds));
        res.status(429).json({ error: options.message });
        return;
      }

      next();
    } catch (error) {
      console.error("[rate-limit] fallback to allow request", error);
      next();
    }
  };
};
