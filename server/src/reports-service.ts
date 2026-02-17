import { config } from "./config";
import { reportsRouter } from "./routes/reports";
import { startService } from "./utils/startService";

void startService({
  serviceName: "reports-service",
  port: config.servicePort,
  installRoutes: (app) => {
    app.use(reportsRouter);
  }
});
