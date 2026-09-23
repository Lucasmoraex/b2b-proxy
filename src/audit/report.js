import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

export async function writeCustomerAuditReport(report, { cwd = process.cwd(), fsImpl = fs } = {}) {
  const directory = path.resolve(cwd, ".shopify-audit-reports");
  await fsImpl.mkdir(directory, { recursive: true, mode: 0o700 });
  await fsImpl.chmod(directory, 0o700);
  const timestamp = report.generated_at.replace(/[:.]/g, "-");
  const prefix = report.report_type === "shopify_customer_duplicate_review" ? "duplicate-review" : "customers";
  const filename = `${prefix}-${timestamp}-${crypto.randomUUID()}.json`;
  const reportPath = path.join(directory, filename);
  await fsImpl.writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, { flag: "wx", mode: 0o600 });
  await fsImpl.chmod(reportPath, 0o600);
  return reportPath;
}
