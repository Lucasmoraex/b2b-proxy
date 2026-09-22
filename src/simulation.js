import { ExternalServiceError } from "./errors.js";

const CONFIRMATION = "ENABLE_ISOLATED_SIMULATION";
const SCENARIOS = new Set(["active", "inactive", "unavailable"]);

export function assertSimulationSafety(config, { role = "web" } = {}) {
  if (!config.simulationMode) return;
  if (!new Set(["development", "staging", "test"]).has(config.environment)) {
    throw new Error("Simulation mode requires B2B_ENVIRONMENT=development, staging, or test");
  }
  if (config.nodeEnv === "production") throw new Error("Simulation mode is forbidden when NODE_ENV=production");
  if (config.simulationConfirmation !== CONFIRMATION) throw new Error("Simulation mode confirmation is missing");
  if (config.shopifyToken || config.shopifyClientId || config.shopifyClientSecret || config.registryToken) {
    throw new Error("Simulation mode refuses real external-service credentials");
  }
  if (config.shop && !config.shop.endsWith(".invalid")) throw new Error("Simulation mode requires an empty or .invalid Shopify host");
  if (role === "web" && !config.shopifyWebhookSecret.startsWith("sim_")) throw new Error("Simulation mode requires a sim_ webhook secret");
  if (config.autoApprove || config.enableLegacyMutations) throw new Error("Simulation mode refuses auto-approval and legacy mutations");
  if (config.isRender && config.environment === "staging" && !config.renderServiceName.toLowerCase().includes("staging")) {
    throw new Error("Simulation mode on Render requires a service name containing staging");
  }
}

export class SimulatedRegistryClient {
  constructor({ scenario = "active" } = {}) { this.setScenario(scenario); }
  setScenario(scenario) {
    if (!SCENARIOS.has(scenario)) throw new Error("Unsupported simulated registry scenario");
    this.scenario = scenario;
  }
  getScenario() { return this.scenario; }
  async checkCnpj() {
    if (this.scenario === "unavailable") throw new ExternalServiceError("registry", "registry_unavailable");
    return {
      found: true,
      active: this.scenario === "active",
      status: this.scenario === "active" ? "ATIVA" : "INATIVA",
      checkedAt: new Date().toISOString(),
    };
  }
}

export class SimulatedShopifyClient {
  constructor({ store }) { this.store = store; }
  async updatePhone(customerId, phone) { await this.store.setSimulationPhone(customerId, phone); }
  async setMetafields(customerId, fields) { await this.store.setSimulationMetafields(customerId, fields); }
  async addTags(customerId, tags) { await this.store.addSimulationTags(customerId, tags); }
  async removeTags(customerId, tags) { await this.store.removeSimulationTags(customerId, tags); }
  async getCustomerState(customerId) { return this.store.getSimulationCustomer(customerId); }
}

export const SIMULATION_CONFIRMATION = CONFIRMATION;
