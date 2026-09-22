import { redact } from "./security.js";

export function createLogger(sink = console) {
  const write = (level, event, context = {}) => {
    const line = JSON.stringify({ level, event, ...redact(context) });
    const fn = level === "error" ? sink.error : level === "warn" ? sink.warn : sink.log;
    fn.call(sink, line);
  };
  return {
    info: (event, context) => write("info", event, context),
    warn: (event, context) => write("warn", event, context),
    error: (event, context) => write("error", event, context),
  };
}
