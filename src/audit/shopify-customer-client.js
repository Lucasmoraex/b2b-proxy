import { ExternalServiceError } from "../errors.js";
import { fetchWithTimeout } from "../clients/http.js";
import { recordReadOnlyError } from "./read-only-telemetry.js";

export const CUSTOMER_AUDIT_QUERY = `query AuditCustomers($first: Int!, $after: String) {
  customers(first: $first, after: $after, sortKey: ID) {
    nodes {
      id
      email
      phone
      tags
      note
      cnpj: metafield(namespace: "custom", key: "cnpj") { value }
      cjnpj: metafield(namespace: "custom", key: "cjnpj") { value }
      cnpjStatus: metafield(namespace: "custom", key: "cnpj_status") { value }
    }
    pageInfo { hasNextPage endCursor }
  }
}`;

export function assertReadOnlyGraphql(document) {
  if (typeof document !== "string") throw new Error("audit_query_required");
  const withoutComments = document.replace(/#[^\r\n]*/g, "").trim();
  if (!/^query\b/.test(withoutComments)) throw new Error("audit_query_only");
  if (/\b(?:mutation|subscription)\b/.test(withoutComments)) throw new Error("audit_query_only");
  if (document !== CUSTOMER_AUDIT_QUERY) throw new Error("audit_query_not_allowlisted");
  return document;
}

const retryAfterMs = (response) => {
  const raw = response.headers?.get?.("retry-after");
  if (!raw) return null;
  const seconds = Number(raw);
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const date = Date.parse(raw);
  return Number.isFinite(date) ? Math.max(0, date - Date.now()) : null;
};

const throttleDelayMs = (body) => {
  const status = body?.extensions?.cost?.throttleStatus;
  const requested = Number(body?.extensions?.cost?.requestedQueryCost);
  const available = Number(status?.currentlyAvailable);
  const restoreRate = Number(status?.restoreRate);
  if (![requested, available, restoreRate].every(Number.isFinite) || restoreRate <= 0) return null;
  return Math.max(0, Math.ceil(((requested - available) / restoreRate) * 1000));
};

const isThrottled = (body) => body?.errors?.some((error) => error?.extensions?.code === "THROTTLED");
const sleepDefault = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

export class ReadOnlyShopifyCustomerClient {
  #fetchImpl;
  #url;
  #token;
  #timeoutMs;
  #maxRetries;
  #pageSize;
  #sleep;
  #logger;
  #telemetry;

  constructor({
    fetchImpl,
    shopDomain,
    token,
    apiVersion,
    timeoutMs = 8000,
    maxRetries = 4,
    pageSize = 100,
    sleep = sleepDefault,
    logger = { warn() {} },
    telemetry,
  }) {
    this.#fetchImpl = fetchImpl;
    this.#url = `https://${shopDomain}/admin/api/${apiVersion}/graphql.json`;
    this.#token = token;
    this.#timeoutMs = timeoutMs;
    this.#maxRetries = maxRetries;
    this.#pageSize = pageSize;
    this.#sleep = sleep;
    this.#logger = logger;
    this.#telemetry = telemetry;
  }

  async #retry({ attempt, reason, suggestedDelayMs = null }) {
    const canRetry = attempt < this.#maxRetries;
    recordReadOnlyError(this.#telemetry, reason, { retried: canRetry });
    if (!canRetry) throw new ExternalServiceError("shopify", "shopify_audit_unavailable");
    const exponential = Math.min(30_000, 500 * (2 ** attempt));
    const delayMs = Math.min(30_000, Math.max(exponential, suggestedDelayMs || 0));
    this.#logger.warn("shopify_audit_query_retry", { attempt: attempt + 1, reason, delayMs });
    await this.#sleep(delayMs);
  }

  async #executeQuery(document, variables) {
    const query = assertReadOnlyGraphql(document);
    for (let attempt = 0; attempt <= this.#maxRetries; attempt += 1) {
      let response;
      try {
        response = await fetchWithTimeout(this.#fetchImpl, this.#url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": this.#token,
          },
          body: JSON.stringify({ query, variables }),
        }, this.#timeoutMs, "shopify");
      } catch (error) {
        await this.#retry({ attempt, reason: "network" });
        continue;
      }

      if (response.status === 429 || response.status >= 500) {
        await this.#retry({
          attempt,
          reason: response.status === 429 ? "throttled_http" : "server_error",
          suggestedDelayMs: retryAfterMs(response),
        });
        continue;
      }
      if (!response.ok) {
        recordReadOnlyError(this.#telemetry, "http_client_error");
        throw new ExternalServiceError("shopify", "shopify_audit_unavailable");
      }

      const body = await response.json().catch(() => null);
      if (!body) {
        recordReadOnlyError(this.#telemetry, "invalid_response");
        throw new ExternalServiceError("shopify", "shopify_audit_unavailable");
      }
      if (isThrottled(body)) {
        await this.#retry({ attempt, reason: "throttled_graphql", suggestedDelayMs: throttleDelayMs(body) });
        continue;
      }
      if (body.errors?.length || !body.data) {
        recordReadOnlyError(this.#telemetry, "graphql_error");
        throw new ExternalServiceError("shopify", "shopify_audit_query_failed");
      }
      return body.data;
    }
    throw new ExternalServiceError("shopify", "shopify_audit_unavailable");
  }

  async *customerPages() {
    let after = null;
    const seenCursors = new Set();
    do {
      const data = await this.#executeQuery(CUSTOMER_AUDIT_QUERY, { first: this.#pageSize, after });
      const connection = data?.customers;
      if (!connection || !Array.isArray(connection.nodes) || !connection.pageInfo) {
        recordReadOnlyError(this.#telemetry, "invalid_page");
        throw new ExternalServiceError("shopify", "shopify_audit_query_failed");
      }
      yield connection.nodes;
      if (!connection.pageInfo.hasNextPage) return;
      const nextCursor = connection.pageInfo.endCursor;
      if (typeof nextCursor !== "string" || !nextCursor || seenCursors.has(nextCursor)) {
        recordReadOnlyError(this.#telemetry, "pagination_error");
        throw new ExternalServiceError("shopify", "shopify_audit_pagination_failed");
      }
      seenCursors.add(nextCursor);
      after = nextCursor;
    } while (true);
  }
}
