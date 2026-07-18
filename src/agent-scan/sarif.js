/**
 * SARIF 2.1.0 emitter for blast-radius findings — makes results show up in
 * the GitHub Security tab via upload-sarif.
 */

const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

const LEVEL = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note' };

/**
 * @param {import('./engine.js').Finding[]} findings
 * @param {{version: string, artifactUri?: string}} opts
 * @returns {object} SARIF 2.1.0 log object.
 */
export function toSarif(findings, opts) {
  const rulesById = new Map();
  for (const f of findings) {
    if (!rulesById.has(f.ruleId)) {
      rulesById.set(f.ruleId, {
        id: f.ruleId,
        name: f.ruleId.replace(/-/g, ''),
        shortDescription: { text: f.title },
        fullDescription: { text: f.description },
        help: { text: f.remediation },
        properties: { category: f.category },
      });
    }
  }
  const ruleIndex = new Map([...rulesById.keys()].map((id, i) => [id, i]));

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Shieldly Agent Blast-Radius',
            informationUri: 'https://www.shieldly.io',
            version: opts.version,
            rules: [...rulesById.values()],
          },
        },
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          ruleIndex: ruleIndex.get(f.ruleId),
          level: LEVEL[f.severity] || 'warning',
          message: {
            text: `${f.title} — ${f.description}${
              f.matchedActions.length ? ` Granted actions: ${f.matchedActions.join(', ')}.` : ''
            } Fix: ${f.remediation}`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: opts.artifactUri || sourceToUri(f.source) },
              },
            },
          ],
          properties: { category: f.category, severity: f.severity, source: f.source },
        })),
      },
    ],
  };
}

/** Derive a plausible artifact URI from a finding source label. */
function sourceToUri(source) {
  const filePart = String(source || '')
    .split(' · ')[0]
    .trim();
  // SARIF artifactLocation.uri must be a valid URI reference — strip spaces.
  return filePart.replace(/\s/g, '%20') || 'policy.json';
}
