import { buildRuntime } from "./src/runtime.js";

const runtime = buildRuntime();

const server = runtime.app.listen(runtime.config.port, () => {
  runtime.logger.info("server_started", { port: runtime.config.port });
});

const shutdown = () => {
  server.close(async () => {
    await runtime.close();
    process.exit(0);
  });
};

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
