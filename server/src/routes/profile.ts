import { Router } from "express";
import { z } from "zod";
import { authenticateAccessToken, requirePermission } from "../middleware/auth";
import { get, run } from "../db";

const updateProfileSchema = z.object({
  display_name: z.string().min(1).max(120).optional(),
  email: z.string().email().optional(),
  department: z.string().min(1).max(100).optional(),
  title: z.string().min(1).max(100).optional(),
  metadata: z.record(z.unknown()).optional()
});

export const profileRouter = Router();

profileRouter.get(
  "/api/profile/me",
  authenticateAccessToken,
  requirePermission("profile:read"),
  async (req, res, next) => {
    try {
      if (!req.user) {
        res.status(401).json({ error: "Unauthorized" });
        return;
      }

      const row = await get<{
        id: number;
        username: string;
        display_name: string;
        email: string | null;
        role: string;
        department: string | null;
        title: string | null;
        profile_metadata: Record<string, unknown>;
        preferences: Record<string, unknown>;
      }>(
        `SELECT u.id, u.username, u.display_name, u.email, u.role,
                p.department, p.title,
                p.metadata AS profile_metadata,
                pref.preferences
         FROM users u
         LEFT JOIN user_profiles p ON p.user_id = u.id
         LEFT JOIN user_preferences pref ON pref.user_id = u.id
         WHERE u.id = $1`,
        [req.user.id]
      );

      if (!row) {
        res.status(404).json({ error: "User not found" });
        return;
      }

      res.status(200).json({
        id: row.id,
        username: row.username,
        display_name: row.display_name,
        email: row.email,
        role: row.role,
        profile: {
          department: row.department,
          title: row.title,
          metadata: row.profile_metadata ?? {}
        },
        preferences: row.preferences ?? {}
      });
    } catch (error) {
      next(error);
    }
  }
);

profileRouter.patch(
  "/api/profile/me",
  authenticateAccessToken,
  requirePermission("profile:write"),
  async (req, res, next) => {
    try {
      if (!req.user) {
        res.status(401).json({ error: "Unauthorized" });
        return;
      }

      const payload = updateProfileSchema.parse(req.body);

      if (payload.display_name || payload.email) {
        await run(
          `UPDATE users
           SET display_name = COALESCE($2, display_name),
               email = COALESCE($3, email),
               updated_at = NOW()
           WHERE id = $1`,
          [req.user.id, payload.display_name ?? null, payload.email ?? null]
        );
      }

      if (payload.department || payload.title || payload.metadata) {
        await run(
          `INSERT INTO user_profiles (user_id, department, title, metadata)
           VALUES ($1, $2, $3, $4::jsonb)
           ON CONFLICT (user_id)
           DO UPDATE SET department = COALESCE(EXCLUDED.department, user_profiles.department),
                         title = COALESCE(EXCLUDED.title, user_profiles.title),
                         metadata = user_profiles.metadata || EXCLUDED.metadata,
                         updated_at = NOW()`,
          [req.user.id, payload.department ?? null, payload.title ?? null, JSON.stringify(payload.metadata ?? {})]
        );
      }

      res.status(200).json({ status: "ok" });
    } catch (error) {
      next(error);
    }
  }
);
