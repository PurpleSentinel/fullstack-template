import { Request } from "express";
import { run } from "../db";

type AuditEntry = {
  action: string;
  resource?: string;
  statusCode?: number;
  metadata?: Record<string, unknown>;
  req?: Request;
  actor?: {
    userId?: number;
    username?: string;
    role?: string;
  };
};

export const writeAuditLog = async (entry: AuditEntry): Promise<void> => {
  const method = entry.req?.method;
  const path = entry.req?.originalUrl;
  const sourceIp = entry.req?.ip;
  const userAgent = entry.req?.header("user-agent") ?? undefined;

  await run(
    `INSERT INTO audit_logs (
      user_id, username, role, action, resource,
      http_method, http_path, status_code,
      source_ip, user_agent, metadata
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb)`,
    [
      entry.actor?.userId ?? null,
      entry.actor?.username ?? null,
      entry.actor?.role ?? null,
      entry.action,
      entry.resource ?? null,
      method ?? null,
      path ?? null,
      entry.statusCode ?? null,
      sourceIp ?? null,
      userAgent ?? null,
      JSON.stringify(entry.metadata ?? {})
    ]
  );
};
