export function historicalAdvisoryLockKeys(shopDomain, claims) {
  return [...new Set(claims.map((claim) => `${shopDomain}:${claim.type}:${claim.valueHash}`))].sort();
}

export function historicalPromotionLockKey(shopDomain) {
  return `${shopDomain}:historical-identity-promotion:v1`;
}

export async function acquireHistoricalPromotionSharedLock(client, shopDomain) {
  const key = historicalPromotionLockKey(shopDomain);
  await client.query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))", [key]);
  return key;
}

export async function acquireHistoricalPromotionExclusiveLock(client, shopDomain) {
  const key = historicalPromotionLockKey(shopDomain);
  await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [key]);
  return key;
}

export async function acquireHistoricalAdvisoryLocks(client, shopDomain, claims) {
  const keys = historicalAdvisoryLockKeys(shopDomain, claims);
  for (const key of keys) {
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [key]);
  }
  return keys;
}
