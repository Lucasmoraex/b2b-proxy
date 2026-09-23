const ERROR_CATEGORIES = new Set([
  "network",
  "throttled_http",
  "server_error",
  "throttled_graphql",
  "http_client_error",
  "invalid_response",
  "graphql_error",
  "invalid_page",
  "pagination_error",
]);

export function createReadOnlyTelemetry() {
  return { retriesTotal: 0, errorsByCategory: new Map() };
}

export function recordReadOnlyError(telemetry, category, { retried = false } = {}) {
  if (!telemetry || !ERROR_CATEGORIES.has(category)) return;
  telemetry.errorsByCategory.set(category, (telemetry.errorsByCategory.get(category) || 0) + 1);
  if (retried) telemetry.retriesTotal += 1;
}

export function readOnlyTelemetrySummary(telemetry) {
  if (!telemetry) return { retries_total: 0, errors_by_category: {} };
  return {
    retries_total: Number(telemetry.retriesTotal) || 0,
    errors_by_category: Object.fromEntries([...telemetry.errorsByCategory.entries()].sort(([left], [right]) => left.localeCompare(right))),
  };
}
