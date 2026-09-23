const SAFE_TOKEN = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$/;
const SAFE_PATH = /^\/[a-zA-Z0-9_/:.*-]{0,255}$/;
const SAFE_METHODS = new Set(["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]);

const integer = (value, max = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(value) && value >= 0 && value <= max;
const token = (value) => typeof value === "string" && SAFE_TOKEN.test(value);

const FIELD_RULES = Object.freeze({
  requestId: token,
  method: (value) => typeof value === "string" && SAFE_METHODS.has(value),
  path: (value) => typeof value === "string" && SAFE_PATH.test(value) && !value.includes("?") && !value.includes("#"),
  status: (value) => integer(value, 599) && value >= 100,
  elapsedMs: (value) => integer(value, 24 * 60 * 60 * 1000),
  durationMs: (value) => integer(value, 24 * 60 * 60 * 1000),
  delayMs: (value) => integer(value, 60 * 60 * 1000),
  port: (value) => integer(value, 65535) && value > 0,
  operation: token,
  code: token,
  category: token,
  reason: token,
  attempt: (value) => integer(value, 10_000),
  attempts: (value) => integer(value, 10_000),
  terminal: (value) => typeof value === "boolean",
  importStatus: token,
  action: token,
});

export function allowlistedLogContext(context) {
  if (!context || typeof context !== "object" || Array.isArray(context) || context instanceof Error) return {};
  const safe = {};
  for (const [key, value] of Object.entries(context)) {
    const rule = FIELD_RULES[key];
    if (rule?.(value)) safe[key] = value;
  }
  return safe;
}

export function createLogger(sink = console) {
  const write = (level, event, context = {}) => {
    const safeEvent = token(event) ? event : "invalid_log_event";
    const line = JSON.stringify({ level, event: safeEvent, ...allowlistedLogContext(context) });
    const fn = level === "error" ? sink.error : level === "warn" ? sink.warn : sink.log;
    fn.call(sink, line);
  };
  return {
    info: (event, context) => write("info", event, context),
    warn: (event, context) => write("warn", event, context),
    error: (event, context) => write("error", event, context),
  };
}
