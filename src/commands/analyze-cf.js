import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  apiPost,
  apiPostDemo,
  consumeDemoCount,
  demoExhausted,
  demoExhaustedMessage,
  getApiKey,
  printResults,
  readFileSafe,
} from '../utils.js';

const HELP = `
Usage: shieldly analyze-cf <template-file-or-dir> [options]

Analyze a CloudFormation template (or directory of templates) for security issues using AI.

Arguments:
  template-file-or-dir  Path to a JSON CF template, or a directory (e.g. cdk.out/)
                        containing synthesized stacks. All *.template.json files are
                        analyzed automatically.

Options:
  --format <fmt>    Output format: table | json  (default: table)
  --api-key <key>   API key (or set SHIELDLY_API_KEY env var)
  -h, --help        Show this help

Authentication:
  No key needed for demo mode (rate-limited). Set SHIELDLY_API_KEY for full access.
  Get an API key (Builder plan or above): https://www.shieldly.io/app/api

Examples:
  shieldly analyze-cf template.json
  shieldly analyze-cf cdk.out/
  shieldly analyze-cf cdk.out/ --format json

CDK integration (add to package.json scripts):
  "synth:check": "cdk synth && shieldly analyze-cf cdk.out/"

cdk.json hook (runs after every cdk synth):
  {
    "hooks": {
      "afterSynth": ["sh", "-c", "shieldly analyze-cf cdk.out/ || true"]
    }
  }
`;

/**
 * Read CDK manifest.json and return the template files for the current synthesis.
 * Returns null if the directory is not a CDK output dir or manifest is unreadable.
 */
function readCDKManifest(dirPath) {
  try {
    const raw = readFileSync(join(dirPath, 'manifest.json'), 'utf8');
    const manifest = JSON.parse(raw);
    if (!manifest.artifacts || typeof manifest.artifacts !== 'object') return null;
    const files = Object.values(manifest.artifacts)
      .filter((a) => a.type === 'aws:cloudformation:stack' && a.properties?.templateFile)
      .map((a) => join(dirPath, a.properties.templateFile))
      .filter((p) => existsSync(p));
    return files.length > 0 ? files : null;
  } catch {
    return null;
  }
}

function findTemplates(dirPath) {
  // Prefer CDK manifest — authoritative list of current-synthesis stacks only.
  const fromManifest = readCDKManifest(dirPath);
  if (fromManifest) return fromManifest;

  // Fallback: glob for any *.template.json (non-CDK CF directories)
  const results = [];
  let entries;
  try {
    entries = readdirSync(dirPath, { withFileTypes: true });
  } catch {
    return results;
  }
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const name = entry.name;
    if (name.endsWith('.template.json') || name.endsWith('.template.yaml')) {
      results.push(join(dirPath, name));
    }
  }
  return results;
}

async function analyzeOne(filePath, apiKey, format, index, total) {
  const templateContent = readFileSync(filePath, 'utf8');
  if (format !== 'json' && total > 1) {
    process.stdout.write(`[${index}/${total}] Analyzing ${filePath}…\n`);
  } else if (format !== 'json') {
    process.stdout.write(`Analyzing ${filePath}…\n`);
  }
  const data = apiKey
    ? await apiPost('/v1/analyze/cf', { template: templateContent }, apiKey)
    : await apiPostDemo('/api/demo/analyze-iam', { template: templateContent, policyType: 'cf' });
  // Count the demo analysis only after a delivered, non-cached result — cache hits
  // consume no server quota, so the local counter must not burn one either.
  if (!apiKey && !data.cached) consumeDemoCount();
  return { filePath, data };
}

export async function analyzeCF(args) {
  if (args.includes('-h') || args.includes('--help') || args.length === 0) {
    console.log(HELP);
    return;
  }

  const fmtIdx = args.indexOf('--format');
  const format = fmtIdx !== -1 ? args[fmtIdx + 1] : 'table';

  if (fmtIdx !== -1 && !['table', 'json'].includes(format)) {
    console.error(`Error: invalid --format "${format}". Use: table | json`);
    process.exit(1);
  }

  const keyIdx = args.indexOf('--api-key');
  const apiKey = getApiKey(keyIdx !== -1 ? args[keyIdx + 1] : null);

  // Track indices consumed by --flag value pairs so we don't pick a flag
  // value as the positional target argument (e.g. --api-key sk_... dir/).
  const usedIdx = new Set();
  for (const idx of [fmtIdx, keyIdx]) {
    if (idx !== -1) {
      usedIdx.add(idx);
      usedIdx.add(idx + 1);
    }
  }
  const target = args.find((a, i) => !usedIdx.has(i) && !a.startsWith('--'));
  if (!target) {
    console.error('Error: template-file-or-dir argument is required');
    process.exit(1);
  }

  // Demo allowance is spent — require a key before doing any work.
  if (!apiKey && demoExhausted()) {
    console.error(demoExhaustedMessage());
    process.exit(1);
  }

  if (!apiKey && format !== 'json') {
    console.log(
      'Demo mode (rate-limited, no signup required). Get an API key (Builder plan or above) for higher limits: https://www.shieldly.io/app/api'
    );
  }

  // Detect directory vs single file
  const stat = statSync(target, { throwIfNoEntry: false });
  if (!stat) {
    console.error(`Error: path not found: ${target}`);
    process.exit(1);
  }

  if (stat.isDirectory()) {
    const templates = findTemplates(target);
    if (templates.length === 0) {
      console.error(
        `Error: no CloudFormation templates (*.template.json / *.template.yaml) found in ${target}\n` +
          'Run "cdk synth" first to generate stack templates.'
      );
      process.exit(1);
    }

    if (format !== 'json') {
      console.log(`Found ${templates.length} stack template(s) in ${target}\n`);
    }

    const allResults = [];
    let overallCriticals = 0;
    let overallHighs = 0;

    for (let i = 0; i < templates.length; i++) {
      // Stop consuming once the demo allowance is spent mid-batch.
      if (!apiKey && demoExhausted()) {
        if (format !== 'json') {
          console.error(
            '\nDemo allowance reached — remaining stacks skipped. Get an API key (Builder plan or above): https://www.shieldly.io/app/api'
          );
        }
        break;
      }
      try {
        const { filePath, data } = await analyzeOne(
          templates[i],
          apiKey,
          format,
          i + 1,
          templates.length
        );
        allResults.push({ filePath, data });
        overallCriticals += (data.findings || []).filter(
          (f) => f.severity?.toUpperCase() === 'CRITICAL'
        ).length;
        overallHighs += (data.findings || []).filter(
          (f) => f.severity?.toUpperCase() === 'HIGH'
        ).length;
        // For table format, print each result immediately
        if (format !== 'json') printResults(data, format);
      } catch (err) {
        console.error(`Error analyzing ${templates[i]}: ${err.message}`);
        // Stop the batch on a demo rate-limit — every remaining stack would 429 too.
        if (!apiKey && /rate limit/i.test(err.message)) break;
      }
    }

    if (format === 'json') {
      // Emit a single JSON array so output is valid for piping to jq/scripts
      console.log(
        JSON.stringify(
          allResults.map(({ filePath, data }) => ({ stack: filePath, ...data })),
          null,
          2
        )
      );
    } else if (templates.length > 1) {
      const totalFindings = allResults.reduce((n, r) => n + (r.data.findings || []).length, 0);
      console.log(
        `\nSummary: ${templates.length} stacks · ${totalFindings} total findings · ${overallCriticals} critical · ${overallHighs} high`
      );
    }

    if (overallCriticals > 0 || overallHighs > 0) {
      process.exit(1);
    }
    return;
  }

  // Single file path
  const templateContent = readFileSafe(target);
  if (format !== 'json') {
    console.log(`Analyzing ${target}…`);
  }

  try {
    const data = apiKey
      ? await apiPost('/v1/analyze/cf', { template: templateContent }, apiKey)
      : await apiPostDemo('/api/demo/analyze-iam', { template: templateContent, policyType: 'cf' });
    printResults(data, format);

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
