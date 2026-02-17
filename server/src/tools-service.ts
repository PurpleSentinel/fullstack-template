import { config } from "./config";
import { toolsRouter } from "./routes/tools";
import { startService } from "./utils/startService";

void startService({
  serviceName: "tools-service",
  port: config.servicePort,
  installRoutes: (app) => {
    app.use(toolsRouter);
  }
});
