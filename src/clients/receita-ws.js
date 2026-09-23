import { ExternalServiceError } from "../errors.js";
import { fetchWithTimeout } from "./http.js";

export function assertReceitaWsAuthConfig({ token = "", tokenMode = "bearer" }) {
  if (!new Set(["bearer", "none"]).has(tokenMode)) throw new Error("registry_token_mode_invalid");
  if (tokenMode === "none" && token) throw new Error("registry_token_forbidden_in_none_mode");
}

export class ReceitaWsClient {
  constructor({ fetchImpl, baseUrl, token = "", tokenMode = "bearer", timeoutMs = 8000 }) {
    assertReceitaWsAuthConfig({ token, tokenMode });
    this.fetchImpl = fetchImpl;
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.token = token;
    this.tokenMode = tokenMode;
    this.timeoutMs = timeoutMs;
  }

  async checkCnpj(cnpj) {
    let url = `${this.baseUrl}/cnpj/${cnpj}`;
    const headers = {};
    if (this.token && this.tokenMode === "bearer") headers.Authorization = `Bearer ${this.token}`;
    const response = await fetchWithTimeout(this.fetchImpl, url, { headers }, this.timeoutMs, "registry");
    if (!response.ok) throw new ExternalServiceError("registry", "registry_unavailable");
    let data;
    try {
      data = await response.json();
    } catch (error) {
      throw new ExternalServiceError("registry", "registry_unavailable", { cause: error });
    }
    const status = String(data?.situacao ?? data?.situacao_cadastral ?? "").trim().toUpperCase();
    const providerAccepted = data?.status === "OK" || Boolean(data?.nome || data?.razao || data?.razao_social);
    return {
      found: providerAccepted,
      active: providerAccepted && status === "ATIVA",
      status: status || "UNKNOWN",
      checkedAt: new Date().toISOString(),
    };
  }
}
