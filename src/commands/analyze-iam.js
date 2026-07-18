import {
  apiPost,
  apiPostDemo,
  badgeMarkdown,
  consumeDemoCount,
  demoExhausted,
  demoExhaustedMessage,
  getApiKey,
  printResults,
  readFileSafe,
} from '../utils.js';

const HELP = `
Usage: shieldly analyze-iam <policy-file> [options]

Analyze an AWS IAM policy for security issues using AI.

Arguments:
  policy-file       Path to a JSON file containing the IAM policy

Options:
  --type <type>     identity (default) | cross_account
                    Any IAM or resource policy JSON works as 'identity'.
                    'cross_account' expects {"identityPolicy":…,"trustPolicy":…}.
  --format <fmt>    Output format: table | json  (default: table)
  --api-key <key>   API key (or set SHIELDLY_API_KEY env var)
  --badge           Print a shareable score badge (Markdown, for a README)
  -h, --help        Show this help

Examples:
  shieldly analyze-iam policy.json
  shieldly analyze-iam policy.json --type cross_account --format json
  shieldly analyze-iam policy.json --badge
  SHIELDLY_API_KEY=sk_... shieldly analyze-iam policy.json
`;

export async function analyzeIAM(args) {
  if (args.includes('-h') || args.includes('--help') || args.length === 0) {
    console.log(HELP);
    return;
  }

  const typeIdx = args.indexOf('--type');
  const policyType = typeIdx !== -1 ? args[typeIdx + 1] : 'identity';

  const fmtIdx = args.indexOf('--format');
  const format = fmtIdx !== -1 ? args[fmtIdx + 1] : 'table';

  // Validate enums up front so a typo doesn't silently run the wrong analysis.
  if (typeIdx !== -1 && !['identity', 'iam_identity', 'cross_account'].includes(policyType)) {
    console.error(`Error: invalid --type "${policyType}". Use: identity | cross_account`);
    process.exit(1);
  }
  if (fmtIdx !== -1 && !['table', 'json'].includes(format)) {
    console.error(`Error: invalid --format "${format}". Use: table | json`);
    process.exit(1);
  }

  const keyIdx = args.indexOf('--api-key');
  const apiKey = getApiKey(keyIdx !== -1 ? args[keyIdx + 1] : null);

  // Demo allowance is spent — require a key before doing any work.
  if (!apiKey && demoExhausted()) {
    console.error(demoExhaustedMessage());
    process.exit(1);
  }

  // Track indices consumed by --flag value pairs so we don't pick a flag
  // value as the positional file argument (e.g. --api-key sk_... file.json).
  const usedIdx = new Set();
  for (const idx of [typeIdx, fmtIdx, keyIdx]) {
    if (idx !== -1) {
      usedIdx.add(idx);
      usedIdx.add(idx + 1);
    }
  }
  const file = args.find((a, i) => !usedIdx.has(i) && !a.startsWith('--'));
  if (!file) {
    console.error('Error: policy-file argument is required');
    process.exit(1);
  }

  const policyContent = readFileSafe(file);
  try {
    JSON.parse(policyContent);
  } catch {
    console.error('Error: policy-file must be valid JSON');
    process.exit(1);
  }
  // API expects policy as a JSON string, not a parsed object
  const policy = policyContent.trim();

  // Normalize policyType to API values
  const normalizedType =
    policyType === 'identity' || policyType === 'iam_identity'
      ? 'iam_identity'
      : policyType === 'cross_account'
        ? 'cross_account'
        : 'iam_identity';

  if (format !== 'json') {
    console.log(`Analyzing ${file} (type: ${normalizedType})…`);
    if (!apiKey) {
      console.log(
        'Demo mode (rate-limited, no signup required). Get an API key (Builder plan or above) for higher limits: https://www.shieldly.io/app/api'
      );
    }
  }

  try {
    const data = apiKey
      ? await apiPost('/v1/analyze/iam', { policy, policyType: normalizedType }, apiKey)
      : await apiPostDemo('/api/demo/analyze-iam', { policy, policyType: normalizedType });
    // Count the demo analysis only after a delivered, non-cached result — cache hits
    // consume no server quota, so the local counter must not burn one either.
    if (!apiKey && !data.cached) consumeDemoCount();
    printResults(data, format);

    if (args.includes('--badge')) {
      const md = badgeMarkdown(data.score);
      // Keep --format json stdout parseable — badge markdown goes to stderr there.
      if (format === 'json') console.error(md);
      else console.log(md);
    }

    const criticals = (data.findings || []).filter(
      (f) => f.severity?.toUpperCase() === 'CRITICAL'
    ).length;
    const highs = (data.findings || []).filter((f) => f.severity?.toUpperCase() === 'HIGH').length;
    if (criticals > 0 || highs > 0) {
      process.exit(1);
    }
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}
