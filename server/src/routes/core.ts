import { Router } from "express";
import { query } from "../db";

export const coreRouter = Router();

coreRouter.get("/api/components", async (_req, res) => {
  let dbStatus = "degraded";

  try {
    await query("SELECT 1");
    dbStatus = "ok";
  } catch {
    dbStatus = "down";
  }

  res.status(200).json({
    status: dbStatus === "ok" ? "ok" : "degraded",
    checked_at: new Date().toISOString(),
    components: {
      db: dbStatus,
      auth: "unknown",
      tools: "unknown",
      reports: "unknown"
    }
  });
});
