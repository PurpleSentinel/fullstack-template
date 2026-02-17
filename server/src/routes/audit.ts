import { Router } from "express";
import { z } from "zod";
import { authenticateAccessToken, requirePermission } from "../middleware/auth";
import { all } from "../db";

const listAuditSchema = z.object({
  limit: z.coerce.number().min(1).max(500).optional(),
  action: z.string().optional()
});

export const auditRouter = Router();

auditRouter.get(
  "/api/audit/logs",
  authenticateAccessToken,
  requirePermission("audit:read"),
  async (req, res, next) => {
    try {
      const query = listAuditSchema.parse(req.query);
      const limit = query.limit ?? 100;

      const logs = query.action
        ? await all(
            `SELECT id, user_id, username, role, action, resource,
                    http_method, http_path, status_code, source_ip,
                    user_agent, metadata, created_at
             FROM audit_logs
             WHERE action = $1
             ORDER BY created_at DESC
             LIMIT $2`,
            [query.action, limit]
          )
        : await all(
            `SELECT id, user_id, username, role, action, resource,
                    http_method, http_path, status_code, source_ip,
                    user_agent, metadata, created_at
             FROM audit_logs
             ORDER BY created_at DESC
             LIMIT $1`,
            [limit]
          );

      res.status(200).json({ logs });
    } catch (error) {
      next(error);
    }
  }
);
