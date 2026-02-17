import { config } from "./config";
import { auditRouter } from "./routes/audit";
import { authRouter } from "./routes/auth";
import { profileRouter } from "./routes/profile";
import { settingsRouter } from "./routes/settings";
import { startService } from "./utils/startService";

void startService({
  serviceName: "auth-service",
  port: config.servicePort,
  installRoutes: (app) => {
    app.use(authRouter);
    app.use(profileRouter);
    app.use(auditRouter);
    app.use(settingsRouter);
  }
});
