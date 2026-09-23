const sortedUnique = (values) => [...new Set(values)].sort();

const validCnpjFingerprints = (customer) => sortedUnique(
  customer.cnpj_sources
    .filter((source) => source.state === "valid" && source.fingerprint)
    .map((source) => source.fingerprint),
);

const validPhoneFingerprints = (customer) => sortedUnique(
  [customer.phone.official, customer.phone.note]
    .filter((source) => source.state === "valid" && source.fingerprint)
    .map((source) => source.fingerprint),
);

const associationList = (customers, type) => {
  const associations = new Map();
  for (const customer of customers) {
    const sources = type === "cnpj"
      ? customer.cnpj_sources.map((source) => ({ ...source }))
      : [
          { source: "customer.phone", ...customer.phone.official },
          { source: "note", ...customer.phone.note },
        ];
    for (const source of sources) {
      if (source.state !== "valid" || !source.fingerprint) continue;
      if (!associations.has(source.fingerprint)) {
        associations.set(source.fingerprint, { customerIds: new Set(), sources: new Set() });
      }
      const association = associations.get(source.fingerprint);
      association.customerIds.add(customer.customer_id);
      association.sources.add(source.source);
    }
  }
  return [...associations.entries()].map(([valueHash, association]) => ({
    value_hash: valueHash,
    customer_ids: [...association.customerIds].sort(),
    sources: [...association.sources].sort(),
  })).sort((left, right) => left.value_hash.localeCompare(right.value_hash));
};

const consistencyFlags = (customers) => {
  const statuses = new Set(customers.map((customer) => customer.cnpj_status));
  const approvedFlags = new Set(customers.map((customer) => customer.has_b2b_approved));
  const dataQuality = {
    email_missing_or_invalid: customers.filter((customer) => !customer.email.present || !customer.email.valid).length,
    no_valid_cnpj: customers.filter((customer) => validCnpjFingerprints(customer).length === 0).length,
    no_valid_phone: customers.filter((customer) => validPhoneFingerprints(customer).length === 0).length,
    cnpj_status_missing_or_other: customers.filter((customer) => ["missing", "other"].includes(customer.cnpj_status)).length,
  };
  return {
    cnpj_status_consistent: statuses.size <= 1,
    b2b_approved_consistent: approvedFlags.size <= 1,
    status_tag_aligned: customers.every((customer) => (customer.cnpj_status === "approved") === customer.has_b2b_approved),
    has_pending_and_approved: customers.some((customer) => customer.has_b2b_pending && customer.has_b2b_approved),
    data_quality: dataQuality,
    has_invalid_or_incomplete_data: Object.values(dataQuality).some((count) => count > 0),
  };
};

const groupCustomers = (group, customerById) => group.customer_ids.map((customerId) => {
  const customer = customerById.get(customerId);
  if (!customer) throw new Error("duplicate_review_customer_missing");
  return customer;
});

const sizeDistribution = (items) => {
  const distribution = { "2": 0, "3": 0, "4_or_more": 0 };
  for (const item of items) {
    if (item.customer_count === 2) distribution["2"] += 1;
    else if (item.customer_count === 3) distribution["3"] += 1;
    else if (item.customer_count >= 4) distribution["4_or_more"] += 1;
  }
  return distribution;
};

const intersection = (sets) => {
  if (!sets.length) return [];
  return [...sets[0]].filter((value) => sets.slice(1).every((set) => set.has(value))).sort();
};

const connectedComponents = ({ cnpjGroups, phoneGroups, customerById }) => {
  const adjacency = new Map();
  const addNode = (customerId) => {
    if (!adjacency.has(customerId)) adjacency.set(customerId, new Set());
  };
  for (const group of [...cnpjGroups, ...phoneGroups]) {
    for (const customerId of group.customer_ids) addNode(customerId);
    const [first, ...rest] = group.customer_ids;
    for (const customerId of rest) {
      adjacency.get(first).add(customerId);
      adjacency.get(customerId).add(first);
    }
  }

  const visited = new Set();
  const components = [];
  for (const start of [...adjacency.keys()].sort()) {
    if (visited.has(start)) continue;
    const stack = [start];
    const customerIds = [];
    visited.add(start);
    while (stack.length) {
      const current = stack.pop();
      customerIds.push(current);
      for (const neighbor of adjacency.get(current)) {
        if (!visited.has(neighbor)) {
          visited.add(neighbor);
          stack.push(neighbor);
        }
      }
    }
    customerIds.sort();
    const idSet = new Set(customerIds);
    const customers = customerIds.map((customerId) => customerById.get(customerId));
    const cnpjGroupFingerprints = cnpjGroups
      .filter((group) => group.customer_ids.some((customerId) => idSet.has(customerId)))
      .map((group) => group.cnpj_fingerprint).sort();
    const phoneGroupFingerprints = phoneGroups
      .filter((group) => group.customer_ids.some((customerId) => idSet.has(customerId)))
      .map((group) => group.phone_fingerprint).sort();
    const commonCnpjs = intersection(customers.map((customer) => new Set(validCnpjFingerprints(customer))));
    const commonPhones = intersection(customers.map((customer) => new Set(validPhoneFingerprints(customer))));
    const classification = commonCnpjs.length && commonPhones.length
      ? "same_cnpj_same_phone"
      : commonCnpjs.length
        ? "same_cnpj_different_phones"
        : commonPhones.length
          ? "same_phone_different_cnpjs"
          : "complex_transitive";
    components.push({
      component_id: `component-${components.length + 1}`,
      classification,
      customer_count: customerIds.length,
      customer_ids: customerIds,
      cnpj_group_fingerprints: cnpjGroupFingerprints,
      phone_group_fingerprints: phoneGroupFingerprints,
      common_cnpj_fingerprints: commonCnpjs,
      common_phone_fingerprints: commonPhones,
      theoretical_merges: customerIds.length - 1,
      consistency: consistencyFlags(customers),
    });
  }
  return components;
};

export function buildDuplicateReview(auditReport) {
  const indicators = auditReport.customer_indicators;
  if (!Array.isArray(indicators)) throw new Error("duplicate_review_indicators_required");
  const customerById = new Map(indicators.map((customer) => [customer.customer_id, customer]));
  const rawCnpjGroups = auditReport.findings?.duplicate_cnpjs || [];
  const rawPhoneGroups = auditReport.findings?.duplicate_phones || [];

  const cnpjGroups = rawCnpjGroups.map((group) => {
    const customers = groupCustomers(group, customerById);
    const associatedPhones = associationList(customers, "phone");
    const sharedPhones = associatedPhones.filter((association) => association.customer_ids.length > 1);
    return {
      cnpj_fingerprint: group.value_hash,
      customer_count: group.customer_ids.length,
      customer_ids: [...group.customer_ids].sort(),
      associated_phones: associatedPhones,
      has_shared_phone: sharedPhones.length > 0,
      all_customers_share_same_phone: sharedPhones.some((association) => association.customer_ids.length === group.customer_ids.length),
      theoretical_merges: group.customer_ids.length - 1,
      consistency: consistencyFlags(customers),
    };
  }).sort((left, right) => left.cnpj_fingerprint.localeCompare(right.cnpj_fingerprint));

  const phoneGroups = rawPhoneGroups.map((group) => {
    const customers = groupCustomers(group, customerById);
    const associatedCnpjs = associationList(customers, "cnpj");
    const sharedCnpjs = associatedCnpjs.filter((association) => association.customer_ids.length > 1);
    return {
      phone_fingerprint: group.value_hash,
      customer_count: group.customer_ids.length,
      customer_ids: [...group.customer_ids].sort(),
      associated_cnpjs: associatedCnpjs,
      has_shared_cnpj: sharedCnpjs.length > 0,
      all_customers_share_same_cnpj: sharedCnpjs.some((association) => association.customer_ids.length === group.customer_ids.length),
      theoretical_merges: group.customer_ids.length - 1,
      consistency: consistencyFlags(customers),
    };
  }).sort((left, right) => left.phone_fingerprint.localeCompare(right.phone_fingerprint));

  const components = connectedComponents({ cnpjGroups, phoneGroups, customerById });
  const cnpjCustomerIds = new Set(cnpjGroups.flatMap((group) => group.customer_ids));
  const phoneCustomerIds = new Set(phoneGroups.flatMap((group) => group.customer_ids));
  const involvedCustomerIds = new Set([...cnpjCustomerIds, ...phoneCustomerIds]);
  const overlapCustomerIds = [...cnpjCustomerIds].filter((customerId) => phoneCustomerIds.has(customerId));
  const classifications = {
    same_cnpj_same_phone: 0,
    same_cnpj_different_phones: 0,
    same_phone_different_cnpjs: 0,
    complex_transitive: 0,
  };
  for (const component of components) classifications[component.classification] += 1;

  const summary = {
    totals: {
      cnpj_duplicate_groups: cnpjGroups.length,
      phone_duplicate_groups: phoneGroups.length,
      connected_components: components.length,
      customers_involved: involvedCustomerIds.size,
      customers_in_both_duplicate_types: overlapCustomerIds.length,
      components_with_invalid_or_incomplete_data: components.filter((component) => component.consistency.has_invalid_or_incomplete_data).length,
    },
    distributions: {
      cnpj_groups: sizeDistribution(cnpjGroups),
      phone_groups: sizeDistribution(phoneGroups),
      connected_components: sizeDistribution(components),
    },
    classifications,
    overlap: {
      cnpj_only_customers: [...cnpjCustomerIds].filter((customerId) => !phoneCustomerIds.has(customerId)).length,
      phone_only_customers: [...phoneCustomerIds].filter((customerId) => !cnpjCustomerIds.has(customerId)).length,
      both_customer_types: overlapCustomerIds.length,
    },
    theoretical_merges: {
      cnpj_groups_sum: cnpjGroups.reduce((sum, group) => sum + group.theoretical_merges, 0),
      phone_groups_sum: phoneGroups.reduce((sum, group) => sum + group.theoretical_merges, 0),
      connected_components_deduplicated: components.reduce((sum, component) => sum + component.theoretical_merges, 0),
    },
  };

  return {
    report_version: 1,
    report_type: "shopify_customer_duplicate_review",
    generated_at: auditReport.generated_at,
    source: auditReport.source,
    audit_totals: auditReport.totals,
    summary,
    customer_indicators: indicators
      .filter((customer) => involvedCustomerIds.has(customer.customer_id))
      .sort((left, right) => left.customer_id.localeCompare(right.customer_id)),
    cnpj_duplicate_groups: cnpjGroups,
    phone_duplicate_groups: phoneGroups,
    connected_components: components,
  };
}

export function duplicateReviewSummary(review) {
  return review.summary;
}
