import { ExternalServiceError } from "../errors.js";

export async function fetchWithTimeout(fetchImpl, url, options, timeoutMs, service) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...options, signal: controller.signal });
  } catch (error) {
    throw new ExternalServiceError(service, `${service}_unavailable`, { cause: error });
  } finally {
    clearTimeout(timeout);
  }
}
