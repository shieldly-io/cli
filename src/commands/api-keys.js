import { apiDelete, apiGet, apiPost, getApiKey } from '../utils.js';

const HELP = `
Usage: shieldly api-keys <subcommand> [options]

Manage Shieldly API keys.

Subcommands:
  list                        List all your API keys
  create --label <label>      Create a new API key
         --scopes <scopes>    Comma-separated scopes: iam,cf,cost (default: iam,cf)
  revoke <key-id>             Revoke an API key by ID

Options:
  --api-key <key>   API key (or set SHIELDLY_API_KEY env var)
  --format json     Output as JSON
  -h, --help        Show this help

Examples:
  shieldly api-keys list
  shieldly api-keys create --label "CI/CD Key" --scopes iam,cf
  shieldly api-keys revoke key_abc123
`;

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const CYAN = '\x1b[36m';
const RESET = '\x1b[0m';

function formatDate(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

export async function apiKeys(args) {
  if (args.includes('-h') || args.includes('--help') || args.length === 0) {
    console.log(HELP);
    return;
  }

  const sub = args[0];
  const rest = args.slice(1);

  const keyIdx = rest.indexOf('--api-key');
  const authKey = getApiKey(keyIdx !== -1 ? rest[keyIdx + 1] : null);
  const fmtIdx = rest.indexOf('--format');
  const format = fmtIdx !== -1 ? rest[fmtIdx + 1] : 'table';

  if (fmtIdx !== -1 && !['table', 'json'].includes(format)) {
    console.error(`Error: invalid --format "${format}". Use: table | json`);
    process.exit(1);
  }

  if (!authKey) {
    console.error(
      'API key management requires an API key to authenticate.\n' +
        '\n' +
        '  Get an API key (Builder plan or above): https://www.shieldly.io/app/api\n' +
        '\n' +
        'Set SHIELDLY_API_KEY or use --api-key once you have your key.'
    );
    process.exit(1);
  }

  if (sub === 'list') {
    try {
      const data = await apiGet('/v1/api-keys', authKey);
      const keys = data.keys || [];
      if (format === 'json') {
        console.log(JSON.stringify(keys, null, 2));
        return;
      }
      if (keys.length === 0) {
        console.log('No API keys found. Create one at https://www.shieldly.io/app/api');
        return;
      }
      console.log('');
      console.log(`${BOLD}API Keys (${keys.length}):${RESET}`);
      console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
      for (const k of keys) {
        const scopes = (k.scopes || []).join(', ') || 'all';
        console.log(`  ${CYAN}${k.keyId}${RESET}`);
        console.log(`    ${BOLD}Label:${RESET}  ${k.label || '(unlabeled)'}`);
        console.log(`    ${BOLD}Scopes:${RESET} ${scopes}`);
        console.log(`    ${BOLD}Uses:${RESET}   ${k.usageCount || 0}`);
        console.log(`    ${BOLD}Created:${RESET} ${formatDate(k.createdAt)}`);
        console.log('');
      }
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
    return;
  }

  if (sub === 'create') {
    const labelIdx = rest.indexOf('--label');
    const label = labelIdx !== -1 ? rest[labelIdx + 1] : 'CLI Key';
    const scopesIdx = rest.indexOf('--scopes');
    const scopesRaw = scopesIdx !== -1 ? rest[scopesIdx + 1] : 'iam,cf';
    const scopes = scopesRaw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    try {
      const data = await apiPost('/v1/api-keys', { label, scopes }, authKey);
      if (format === 'json') {
        console.log(JSON.stringify(data, null, 2));
        return;
      }
      console.log('');
      console.log(`${BOLD}[OK] API key created${RESET}`);
      console.log(`  ${BOLD}Key ID:${RESET} ${data.keyId}`);
      console.log(`  ${BOLD}API Key:${RESET} ${CYAN}${data.apiKey}${RESET}`);
      console.log(`  ${DIM}Store this key securely — it won't be shown again.${RESET}`);
      console.log('');
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
    return;
  }

  if (sub === 'revoke') {
    // Skip known --option VALUE pairs to avoid treating a key value as the positional arg
    const usedIdx = new Set();
    if (keyIdx !== -1) {
      usedIdx.add(keyIdx);
      usedIdx.add(keyIdx + 1);
    }
    if (fmtIdx !== -1) {
      usedIdx.add(fmtIdx);
      usedIdx.add(fmtIdx + 1);
    }
    const keyId = rest.find((a, i) => !usedIdx.has(i) && !a.startsWith('--'));
    if (!keyId) {
      console.error(
        'Error: key-id argument is required\n  Usage: shieldly api-keys revoke <key-id>'
      );
      process.exit(1);
    }
    try {
      await apiDelete('/v1/api-keys', { keyId }, authKey);
      if (format === 'json') {
        console.log(JSON.stringify({ success: true, keyId }));
        return;
      }
      console.log(`[OK] API key ${keyId} revoked`);
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
    return;
  }

  console.error(`Unknown subcommand: ${sub}`);
  console.log(HELP);
  process.exit(1);
}
