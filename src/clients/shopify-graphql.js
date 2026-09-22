import { ExternalServiceError } from "../errors.js";
import { normalizeEmail } from "../validation.js";
import { fetchWithTimeout } from "./http.js";

const customerGid = (id) => String(id).startsWith("gid://") ? String(id) : `gid://shopify/Customer/${id}`;

export class ShopifyGraphqlClient {
  constructor({ fetchImpl, shop, token, apiVersion, timeoutMs = 8000 }) {
    this.fetchImpl = fetchImpl;
    this.url = `https://${shop}/admin/api/${apiVersion}/graphql.json`;
    this.token = token;
    this.timeoutMs = timeoutMs;
  }

  async execute(query, variables) {
    const response = await fetchWithTimeout(this.fetchImpl, this.url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Shopify-Access-Token": this.token },
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
}

export { customerGid };
