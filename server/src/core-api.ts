import { config } from "./config";
import { coreRouter } from "./routes/core";
import { startService } from "./utils/startService";

void startService({
  serviceName: "core-api",
  port: config.servicePort,
  installRoutes: (app) => {
    app.use(coreRouter);
  }
});
