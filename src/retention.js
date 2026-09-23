const emptySummary = () => ({
  released_registrations: 0,
  released_claims: 0,
  purged_payloads: 0,
  deleted_outbox: 0,
  deleted_webhook_events: 0,
  deleted_fiscal_cache: 0,
  deleted_rate_limit_buckets: 0,
  deleted_admissions: 0,
  deleted_historical_runs: 0,
});

export const RETENTION_EXECUTION_CONFIRMATION = "EXECUTE_B2B_RETENTION";

export class RetentionService {
  constructor({ store, clock = () => new Date(), logger = { info() {} } }) {
    this.store = store;
    this.clock = clock;
    this.logger = logger;
  }

  async run(config) {
    if (!config || !["report-only", "execute"].includes(config.mode)) {
      throw new Error("retention_mode_invalid");
    }
    const input = { ...config, now: this.clock() };
    if (config.mode === "report-only") {
      const summary = await this.store.reportRetentionCandidates(input);
      this.logger.info("retention_report_completed", { operation: "report_only" });
      return { mode: "report-only", ...emptySummary(), ...summary };
    }
    if (!config.enabled) throw new Error("retention_disabled");
    if (config.confirmation !== RETENTION_EXECUTION_CONFIRMATION) {
      throw new Error("retention_confirmation_required");
    }
    if (config.environment === "production" && !config.allowProduction) {
      throw new Error("retention_production_refused");
    }
    const summary = await this.store.applyRetentionBatch(input);
    this.logger.info("retention_batch_completed", { operation: "execute", attempts: 1 });
    return { mode: "execute", ...emptySummary(), ...summary };
  }
}
