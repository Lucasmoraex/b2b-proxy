import { buildWorkerRuntime } from "./runtime.js";

const runtime = buildWorkerRuntime();
let stopping = false;

const stop = () => { stopping = true; };
process.on("SIGINT", stop);
process.on("SIGTERM", stop);

while (!stopping) {
  try {
    const worked = await runtime.worker.runOnce();
    if (!worked) await new Promise((resolve) => setTimeout(resolve, runtime.config.workerPollMs));
  } catch (error) {
    runtime.logger.error("worker_loop_failed", { error });
    await new Promise((resolve) => setTimeout(resolve, runtime.config.workerPollMs));
  }
}

await runtime.close();
