import { Router } from "express";
import { authenticateAccessToken, requirePermission } from "../middleware/auth";

export const toolsRouter = Router();

toolsRouter.get(
  "/api/tools/ping",
  authenticateAccessToken,
  requirePermission("tools:use"),
  (req, res) => {
    res.status(200).json({
      status: "ok",
      message: "tools-service reachable",
      actor: req.user?.username
    });
  }
);
