import { Server } from "http";

export const setupGracefulShutdown = (server: Server, onClose: () => Promise<void>): void => {
  let shuttingDown = false;

  const shutdown = async (signal: NodeJS.Signals): Promise<void> => {
    if (shuttingDown) {
      return;
    }

    shuttingDown = true;
    console.log(`[shutdown] received ${signal}`);

    server.close(async () => {
      try {
        await onClose();
      } catch (error) {
        console.error("[shutdown] error during cleanup", error);
      } finally {
        process.exit(0);
      }
    });

    setTimeout(() => {
      process.exit(1);
    }, 10000).unref();
  };

  process.on("SIGTERM", () => {
    void shutdown("SIGTERM");
  });

  process.on("SIGINT", () => {
    void shutdown("SIGINT");
  });
};
