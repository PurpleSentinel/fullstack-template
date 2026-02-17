import cors from "cors";
import express, { Express, NextFunction, Request, Response } from "express";
import helmet from "helmet";
import morgan from "morgan";

export type ServiceBootstrapOptions = {
  serviceName: string;
  corsOrigin?: string;
  jsonLimit?: string;
};

export const createServiceApp = (options: ServiceBootstrapOptions): Express => {
  const app = express();

  app.disable("x-powered-by");
  app.use(helmet());
  app.use(
    cors({
      origin: options.corsOrigin ?? true,
      credentials: true
    })
  );

  app.use(express.json({ limit: options.jsonLimit ?? "1mb" }));
  app.use(morgan("combined"));

  app.get("/api/health", (_req: Request, res: Response) => {
    res.json({
      status: "ok",
      service: options.serviceName,
      timestamp: new Date().toISOString()
    });
  });

  return app;
};

export const notFoundHandler = (_req: Request, res: Response): void => {
  res.status(404).json({ error: "Not found" });
};

export const errorHandler = (
  error: unknown,
  _req: Request,
  res: Response,
  _next: NextFunction
): void => {
  if (res.headersSent) {
    return;
  }

  if (error instanceof Error) {
    res.status(500).json({ error: process.env.NODE_ENV === "production" ? "Internal server error" : error.message });
    return;
  }

  res.status(500).json({ error: "Internal server error" });
};

export const installDefaultHandlers = (app: Express): void => {
  app.use(notFoundHandler);
  app.use(errorHandler);
};
