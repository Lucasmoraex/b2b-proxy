const DEVELOPMENT_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function parseAllowedOrigins(value = "") {
  return String(value).split(",").map((item) => item.trim()).filter(Boolean).map((origin) => {
    let parsed;
    try {
      parsed = new URL(origin);
    } catch {
      throw new Error("allowed_origin_invalid");
    }
    if (!["http:", "https:"].includes(parsed.protocol)
      || parsed.username || parsed.password || parsed.pathname !== "/"
      || parsed.search || parsed.hash || parsed.origin !== origin) {
      throw new Error("allowed_origin_invalid");
    }
    return origin;
  });
}

export function isDevelopmentOrigin(origin) {
  try {
    const { hostname } = new URL(origin);
    return DEVELOPMENT_HOSTS.has(hostname)
      || hostname === "shopifypreview.com"
      || hostname.endsWith(".shopifypreview.com");
  } catch {
    return false;
  }
}

export function isOriginAllowed(origin, config) {
  if (typeof origin !== "string" || !origin) return false;
  if (config.allowedOrigins.includes(origin)) return true;
  return config.environment !== "production" && isDevelopmentOrigin(origin);
}

export function assertWebHttpSecurityConfig(config) {
  if (!Number.isInteger(config.trustProxyHops) || config.trustProxyHops < 0 || config.trustProxyHops > 10) {
    throw new Error("trust_proxy_hops_invalid");
  }
  if (config.environment === "production") {
    if (!config.trustProxyConfigured) throw new Error("B2B_TRUST_PROXY_HOPS must be explicitly configured in production");
    if (!config.allowedOrigins.length) throw new Error("B2B_ALLOWED_ORIGIN must be configured in production");
    if (config.allowedOrigins.some(isDevelopmentOrigin)) throw new Error("development_origin_forbidden_in_production");
  }
  if (config.keepAliveTimeoutMs >= config.headerTimeoutMs
    || config.headerTimeoutMs > config.httpRequestTimeoutMs) {
    throw new Error("http_timeout_configuration_invalid");
  }
}

export function configureHttpServerTimeouts(server, config) {
  server.headersTimeout = config.headerTimeoutMs;
  server.requestTimeout = config.httpRequestTimeoutMs;
  server.keepAliveTimeout = config.keepAliveTimeoutMs;
  return server;
}
