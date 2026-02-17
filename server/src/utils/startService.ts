import { Express } from "express";
import { closeDb, migrate } from "../db";
import { closeRedis } from "../redis";
import { createServiceApp, installDefaultHandlers } from "./expressBootstrap";
import { setupGracefulShutdown } from "./gracefulShutdown";

type StartServiceOptions = {
  serviceName: string;
  port: number;
  installRoutes: (app: Express) => void;
};

export const startService = async (options: StartServiceOptions): Promise<void> => {
  await migrate();

  const app = createServiceApp({ serviceName: options.serviceName });
  options.installRoutes(app);
  installDefaultHandlers(app);

  const server = app.listen(options.port, () => {
    console.log(`[${options.serviceName}] listening on port ${options.port}`);
  });

  setupGracefulShutdown(server, async () => {
    await Promise.all([closeDb(), closeRedis()]);
  });
};
