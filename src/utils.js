import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

// __CLI_VERSION__ is replaced at build time by esbuild define
const CLI_UA = `Shieldly-CLI/${typeof __CLI_VERSION__ !== 'undefined' ? __CLI_VERSION__ : '0.0.0'}`;

const CONFIG_PATH = join(homedir(), '.shieldly', 'config.json');
const DEFAULT_API = 'https://api.shieldly.io';
const DEFAULT_WEB = 'https://www.shieldly.io';

/** Lifetime demo analyses allowed without an API key (client-side nudge). */
export const DEMO_LIMIT = 5;

function readConfig() {
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function writeConfig(cfg) {
  try {
    mkdirSync(dirname(CONFIG_PATH), { recursive: true });
    writeFileSync(CONFIG_PATH, `${JSON.stringify(cfg, null, 2)}\n`);
  } catch {
    // Non-fatal — if we can't persist the counter, the server per-IP cap still applies.
  }
}

export function getApiKey(cliFlag) {
  if (cliFlag) return cliFlag;
  if (process.env.SHIELDLY_API_KEY) return process.env.SHIELDLY_API_KEY;
  const cfg = readConfig();
  return cfg.apiKey || null;
}

/** Demo analyses already used (client-side counter, persisted in ~/.shieldly/config.json). */
export function getDemoCount() {
  const n = readConfig().demoCount;
  return typeof n === 'number' && n > 0 ? n : 0;
}

/** True when the local lifetime demo allowance is spent. The server per-IP cap is the hard backstop. */
export function demoExhausted() {
  return getDemoCount() >= DEMO_LIMIT;
}

/** Record one consumed demo analysis. Returns remaining local allowance. */
export function consumeDemoCount() {
  const cfg = readConfig();
  cfg.demoCount = getDemoCount() + 1;
  writeConfig(cfg);
  return Math.max(0, DEMO_LIMIT - cfg.demoCount);
}

/** Shared message shown when demo is exhausted (CLI). */
export function demoExhaustedMessage() {
  return (
    `You've used all ${DEMO_LIMIT} free demo analyses.\n` +
    '\n' +
    '  Get an API key (Builder plan or above) for higher limits: https://www.shieldly.io/app/api\n' +
    '\n' +
    'Then set SHIELDLY_API_KEY or pass --api-key.'
  );
}

export function getApiBase() {
  return (process.env.SHIELDLY_API_URL || DEFAULT_API).replace(/\/$/, '');
}

export function getWebBase() {
  return (process.env.SHIELDLY_WEB_URL || DEFAULT_WEB).replace(/\/$/, '');
}

/**
 * Unauthenticated demo analysis. Routes through the website's non-browser demo
 * proxy (ADR-016), which injects the trusted-proxy secret server-side. IAM
 * Advisor only. Bounded by a per-IP daily cap + global demo budget.
 */
export async function apiPostDemo(path, body) {
  const base = getWebBase();
  const res = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'User-Agent': CLI_UA },
    body: JSON.stringify(body),
  });
  if (res.status === 429) {
    throw new Error(
      'Demo rate limit reached. Get an API key (Builder plan or above) for higher limits: https://www.shieldly.io/app/api'
    );
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `API error ${res.status}`);
  }
  return res.json();
}

export async function apiPost(path, body, apiKey) {
  const base = getApiBase();
  const res = await fetch(`${base}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': CLI_UA,
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(body),
  });
  if (res.status === 202) {
    const data = await res.json().catch(() => ({}));
    if (data.jobId) return pollJob(data.jobId, apiKey);
    throw new Error('Analysis queued but no job ID returned — try again');
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `API error ${res.status}`);
  }
  return res.json();
}

async function pollJob(jobId, apiKey) {
  const delays = [2000, 3000, 5000];
  const startMs = Date.now();
  let consecutiveErrors = 0;
  for (let i = 0; i < 180; i++) {
    const delay = delays[Math.min(i, delays.length - 1)];
    await new Promise((r) => setTimeout(r, delay));
    const elapsed = Math.round((Date.now() - startMs) / 1000);
    process.stderr.write(`\rAI-Powered analysis in progress… (${elapsed}s)`);
    let data;
    try {
      data = await apiGet(`/v1/jobs/${encodeURIComponent(jobId)}`, apiKey);
      consecutiveErrors = 0;
    } catch (err) {
      // Transient poll failure must not abandon a job that's still running.
      if (++consecutiveErrors >= 3) {
        process.stderr.write('\n');
        throw err;
      }
      continue;
    }
    if (data.status === 'complete') {
      process.stderr.write('\n');
      return { ...data.result, unitInfo: data.unitInfo };
    }
    if (data.status === 'failed') {
      process.stderr.write('\n');
      throw new Error(data.error || 'Analysis failed');
    }
  }
  process.stderr.write('\n');
  throw new Error('Analysis timed out after polling');
}

export async function apiGet(path, apiKey) {
  const base = getApiBase();
  const res = await fetch(`${base}${path}`, {
    headers: { Authorization: `Bearer ${apiKey}`, 'User-Agent': CLI_UA },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `API error ${res.status}`);
  }
  return res.json();
}

export async function apiDelete(path, body, apiKey) {
  const base = getApiBase();
  const res = await fetch(`${base}${path}`, {
    method: 'DELETE',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': CLI_UA,
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `API error ${res.status}`);
  }
  return res.json();
}

export function readFileSafe(filePath) {
  if (!existsSync(filePath)) {
    console.error(`Error: File not found: ${filePath}`);
    process.exit(1);
  }
  if (statSync(filePath).isDirectory()) {
    console.error(
      `Error: ${filePath} is a directory, not a file.\n  For a CDK output directory, use: shieldly analyze-cf ${filePath}`
    );
    process.exit(1);
  }
  return readFileSync(filePath, 'utf8');
}

const SEV_COLOR = {
  CRITICAL: '\x1b[31m',
  HIGH: '\x1b[33m',
  MEDIUM: '\x1b[36m',
  LOW: '\x1b[32m',
  INFO: '\x1b[90m',
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const CYAN = '\x1b[36m';

export function printResults(data, format) {
  if (format === 'json') {
    console.log(JSON.stringify(data, null, 2));
    return;
  }

  const { score, riskLevel, findings = [], cached, summary, positives = [], unitInfo } = data;
  const scoreStr = score === null || score === undefined ? '—' : `${score}/100`;
  console.log('');
  console.log(`${BOLD}AI-Powered Security Analysis — Shieldly${RESET}`);
  console.log(`${DIM}${'─'.repeat(50)}${RESET}`);
  console.log(`  ${BOLD}Security Score:${RESET}  ${scoreColor(score)}${scoreStr}${RESET}`);
  console.log(
    `  ${BOLD}Risk Level:${RESET}  ${sevColor(riskLevel)}${riskLevel || 'Unknown'}${RESET}`
  );
  if (cached) console.log(`  ${DIM}(cached result)${RESET}`);

  // AI-written summary, when the API returns one.
  if (summary) {
    console.log('');
    console.log(`  ${DIM}${summary}${RESET}`);
  }
  console.log('');

  // What's good — strengths the AI identified.
  if (positives.length > 0) {
    console.log(`${BOLD}What's good:${RESET}`);
    for (const p of positives) {
      console.log(`  ${SEV_COLOR.LOW}[+]${RESET} ${DIM}${p}${RESET}`);
    }
    console.log('');
  }

  if (findings.length === 0) {
    console.log(`  ${CYAN}[PASS] No findings${RESET}`);
  } else {
    console.log(`${BOLD}Findings (${findings.length}):${RESET}`);
    for (const f of findings) {
      const col = SEV_COLOR[(f.severity || '').toUpperCase()] || '';
      console.log(`\n  ${col}[${f.severity}]${RESET} ${BOLD}${f.title}${RESET}`);
      if (f.resource && f.resource !== '*') {
        console.log(`         ${DIM}Resource: ${f.resource}${RESET}`);
      }
      if (f.description) console.log(`         ${DIM}${f.description}${RESET}`);
      if (f.remediation) console.log(`  ${CYAN}Fix:${RESET}  ${f.remediation}`);
    }
  }

  // Usage info for authenticated runs (units consumed against the plan cap).
  if (unitInfo && typeof unitInfo.unitsUsed === 'number' && typeof unitInfo.cap === 'number') {
    console.log('');
    console.log(`  ${DIM}Units used: ${unitInfo.unitsUsed}/${unitInfo.cap}${RESET}`);
  }

  // Demo runs: show the server-reported remaining allowance for this IP.
  if (data.demoInfo && typeof data.demoInfo.analysesRemaining === 'number') {
    console.log('');
    console.log(
      `  ${DIM}Demo analyses remaining: ${data.demoInfo.analysesRemaining}. Get an API key (Builder plan or above) for more: https://www.shieldly.io/app/api${RESET}`
    );
  }
  console.log('');
}

// Score semantics: 100 = perfectly secure (see prompts.js). High is good.
function scoreColor(s) {
  if (s === null || s === undefined) return '';
  if (s >= 80) return '\x1b[32m';
  if (s >= 50) return '\x1b[33m';
  return '\x1b[31m';
}

function sevColor(level) {
  const l = (level || '').toUpperCase();
  return SEV_COLOR[l] || '';
}
