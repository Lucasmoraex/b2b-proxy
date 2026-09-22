import { ExternalServiceError } from "../errors.js";
import { normalizeEmail } from "../validation.js";
import { fetchWithTimeout } from "./http.js";

const customerGid = (id) => String(id).startsWith("gid://") ? String(id) : `gid://shopify/Customer/${id}`;

export class ShopifyGraphqlClient {
  constructor({ fetchImpl, shop, token = "", clientId = "", clientSecret = "", apiVersion, timeoutMs = 8000, clock = () => new Date() }) {
    this.fetchImpl = fetchImpl;
    this.shopHost = shop.includes(".") ? shop : `${shop}.myshopify.com`;
    this.url = `https://${this.shopHost}/admin/api/${apiVersion}/graphql.json`;
    this.token = token;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.timeoutMs = timeoutMs;
    this.clock = clock;
    this.cachedToken = null;
    this.tokenExpiresAt = 0;
  }

  async accessToken() {
    if (this.token) return this.token;
    if (this.cachedToken && this.clock().getTime() < this.tokenExpiresAt - 60_000) return this.cachedToken;
    const body = new URLSearchParams({ grant_type: "client_credentials", client_id: this.clientId, client_secret: this.clientSecret });
    const response = await fetchWithTimeout(this.fetchImpl, `https://${this.shopHost}/admin/oauth/access_token`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body,
    }, this.timeoutMs, "shopify");
    if (!response.ok) throw new ExternalServiceError("shopify", "shopify_unavailable");
    const payload = await response.json().catch(() => null);
    if (!payload?.access_token || !Number.isFinite(payload.expires_in)) throw new ExternalServiceError("shopify", "shopify_unavailable");
    this.cachedToken = payload.access_token;
    this.tokenExpiresAt = this.clock().getTime() + payload.expires_in * 1000;
    return this.cachedToken;
  }

  async execute(query, variables) {
    const response = await fetchWithTimeout(this.fetchImpl, this.url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Shopify-Access-Token": await this.accessToken() },
      body: JSON.stringify({ query, variables }),
    }, this.timeoutMs, "shopify");
    if (!response.ok) throw new ExternalServiceError("shopify", "shopify_unavailable");
    const body = await response.json().catch(() => null);
    if (!body || body.errors?.length) throw new ExternalServiceError("shopify", "shopify_unavailable");
    return body.data;
  }

  static assertNoUserErrors(result) {
    if (result?.userErrors?.length) throw new ExternalServiceError("shopify", "shopify_operation_failed");
  }

  async updatePhone(customerId, phone) {
    const data = await this.execute(`mutation UpdateCustomer($input: CustomerInput!) {
      customerUpdate(input: $input) { customer { id } userErrors { field message } }
    }`, { input: { id: customerGid(customerId), phone } });
    ShopifyGraphqlClient.assertNoUserErrors(data.customerUpdate);
  }

  async setMetafields(customerId, fields) {
    const metafields = fields.map((field) => ({ ...field, ownerId: customerGid(customerId), namespace: "custom" }));
    const data = await this.execute(`mutation SetMetafields($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields: $metafields) { metafields { id key } userErrors { field message code } }
    }`, { metafields });
    ShopifyGraphqlClient.assertNoUserErrors(data.metafieldsSet);
  }

  async addTags(customerId, tags) {
    const data = await this.execute(`mutation AddTags($id: ID!, $tags: [String!]!) {
      tagsAdd(id: $id, tags: $tags) { node { id } userErrors { field message } }
    }`, { id: customerGid(customerId), tags });
    ShopifyGraphqlClient.assertNoUserErrors(data.tagsAdd);
  }

  async removeTags(customerId, tags) {
    const data = await this.execute(`mutation RemoveTags($id: ID!, $tags: [String!]!) {
      tagsRemove(id: $id, tags: $tags) { node { id } userErrors { field message } }
    }`, { id: customerGid(customerId), tags });
    ShopifyGraphqlClient.assertNoUserErrors(data.tagsRemove);
  }

  async getCustomerState(customerId) {
    const data = await this.execute(`query CustomerState($id: ID!) {
      customer(id: $id) { id email phone tags metafields(first: 20, namespace: "custom") { nodes { key value } } }
    }`, { id: customerGid(customerId) });
    return data.customer || null;
  }

  async findCustomerByExactEmail(email) {
    const normalized = normalizeEmail(email);
    const escaped = normalized.replace(/[\\"]/g, "\\$&");
    const data = await this.execute(`query FindCustomer($query: String!) {
      customers(first: 10, query: $query) { nodes { id email } }
    }`, { query: `email:\"${escaped}\"` });
    return (data.customers?.nodes || []).find((customer) => {
      try { return normalizeEmail(customer.email) === normalized; } catch { return false; }
    }) || null;
  }

  async createCustomersCreateWebhook(callbackUrl) {
    const data = await this.execute(`mutation CreateCustomersWebhook($topic: WebhookSubscriptionTopic!, $subscription: WebhookSubscriptionInput!) {
      webhookSubscriptionCreate(topic: $topic, webhookSubscription: $subscription) {
        webhookSubscription { id topic uri }
        userErrors { field message }
      }
    }`, { topic: "CUSTOMERS_CREATE", subscription: { uri: callbackUrl } });
    ShopifyGraphqlClient.assertNoUserErrors(data.webhookSubscriptionCreate);
    return data.webhookSubscriptionCreate.webhookSubscription;
  }
}

export { customerGid };
