import { ExternalServiceError } from "../errors.js";
import { fetchWithTimeout } from "./http.js";

export function assertReceitaWsAuthConfig({ token = "", tokenMode = "bearer" }) {
  if (!new Set(["bearer", "none"]).has(tokenMode)) throw new Error("registry_token_mode_invalid");
  if (tokenMode === "bearer" && !token) throw new Error("registry_token_required_in_bearer_mode");
  if (tokenMode === "none" && token) throw new Error("registry_token_forbidden_in_none_mode");
}

function normalizeBaseUrl(baseUrl) {
  let parsed;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new Error("registry_base_url_invalid");
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("registry_base_url_invalid");
  }
  return parsed.toString().replace(/\/$/, "");
}

function normalizeReturnedCnpj(value) {
  if (typeof value !== "string" || /[^\d.\/-]/.test(value)) return "";
  return value.replace(/\D/g, "");
}

export class ReceitaWsClient {
  constructor({
    fetchImpl,
    baseUrl,
    token = "",
    tokenMode = "bearer",
    maxAgeDays = 7,
    timeoutMs = 60_000,
  }) {
    assertReceitaWsAuthConfig({ token, tokenMode });
    if (!Number.isSafeInteger(maxAgeDays) || maxAgeDays < 0) throw new Error("registry_max_age_days_invalid");
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new Error("registry_timeout_ms_invalid");
    this.fetchImpl = fetchImpl;
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.token = token;
    this.tokenMode = tokenMode;
    this.maxAgeDays = maxAgeDays;
    this.timeoutMs = timeoutMs;
  }

  async checkCnpj(cnpj) {
    const commercial = this.tokenMode === "bearer";
    const path = commercial
      ? `/cnpj/${cnpj}/days/${this.maxAgeDays}?fallback=noCache`
      : `/cnpj/${cnpj}`;
    const url = `${this.baseUrl}${path}`;
    const headers = {};
    if (commercial) headers.Authorization = `Bearer ${this.token}`;
    const response = await fetchWithTimeout(this.fetchImpl, url, { headers }, this.timeoutMs, "registry");
    if (!response.ok) {
      throw new ExternalServiceError("registry", "registry_unavailable", {
        upstreamStatus: Number.isInteger(response.status) ? response.status : undefined,
      });
    }
    let data;
    try {
      data = await response.json();
    } catch (error) {
      throw new ExternalServiceError("registry", "registry_unavailable", { cause: error });
    }
    const status = String(data?.situacao ?? data?.situacao_cadastral ?? "").trim().toUpperCase();
    const returnedCnpj = normalizeReturnedCnpj(data?.cnpj);
    const providerAccepted = data && !Array.isArray(data)
      && data.status === "OK"
      && returnedCnpj === cnpj
      && status
      && status !== "UNKNOWN";
    if (!providerAccepted) throw new ExternalServiceError("registry", "registry_unavailable");
    return {
      found: true,
      active: status === "ATIVA",
      status,
      checkedAt: new Date().toISOString(),
    };
  }
}
