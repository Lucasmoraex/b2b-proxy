import { buildWebRuntime } from "./src/runtime.js";
import { configureHttpServerTimeouts } from "./src/http-security.js";

const runtime = buildWebRuntime();

const server = runtime.app.listen(runtime.config.port, () => {
  runtime.logger.info("server_started", { port: runtime.config.port });
});
configureHttpServerTimeouts(server, runtime.config);

const shutdown = () => {
  server.close(async () => {
    await runtime.close();
    process.exit(0);
  });
};

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
