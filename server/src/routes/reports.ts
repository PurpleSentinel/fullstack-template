import { Router } from "express";
import { authenticateAccessToken, requirePermission } from "../middleware/auth";

export const reportsRouter = Router();

reportsRouter.get(
  "/api/reports/summary",
  authenticateAccessToken,
  requirePermission("reports:read"),
  (_req, res) => {
    res.status(200).json({
      status: "ok",
      generated_at: new Date().toISOString(),
      report: {
        type: "summary",
        rows: 0,
        notes: "Report pipeline scaffolded; implement domain queries next."
      }
    });
  }
);

reportsRouter.post(
  "/api/reports/export",
  authenticateAccessToken,
  requirePermission("reports:read"),
  (_req, res) => {
    res.status(202).json({
      status: "queued",
      message: "Report export queue scaffold is active"
    });
  }
);
