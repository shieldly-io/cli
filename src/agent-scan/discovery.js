/**
 * Agent config auto-discovery — pure fs, offline.
 *
 * Finds AI-agent config files (MCP clients, Claude Code, Claude Desktop) and
 * extracts AWS credential references: profiles, role ARNs, and hardcoded
 * access keys. Never logs file contents — only paths and key-ID suffixes
 * (privacy commitment: no logging of user input).
 */

import { existsSync, readFileSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';

/** Long-lived AWS access key IDs (AKIA = IAM user key; ASIA = temporary, not flagged). */
const ACCESS_KEY_RE = /\bAKIA[0-9A-Z]{16}\b/g;
const ROLE_ARN_RE = /\barn:aws:iam::\d{12}:role\/[A-Za-z0-9+=,.@_/-]+/g;

/** Candidate config files relative to a project directory. */
const PROJECT_CONFIG_FILES = [
  '.mcp.json',
  'mcp.json',
  join('.claude', 'settings.json'),
  join('.claude', 'settings.local.json'),
  join('.cursor', 'mcp.json'),
  join('.vscode', 'mcp.json'),
];

/** Claude Desktop config path per platform. */
function claudeDesktopConfigPath() {
  const os = platform();
  if (os === 'darwin') {
    return join(
      homedir(),
      'Library',
      'Application Support',
      'Claude',
      'claude_desktop_config.json'
    );
  }
  if (os === 'win32') {
    const appData = process.env.APPDATA || join(homedir(), 'AppData', 'Roaming');
    return join(appData, 'Claude', 'claude_desktop_config.json');
  }
  return join(homedir(), '.config', 'Claude', 'claude_desktop_config.json');
}

/** VS Code's user-profile mcp.json (applies across all workspaces), per platform. */
function vscodeGlobalConfigPath() {
  const os = platform();
  if (os === 'darwin') {
    return join(homedir(), 'Library', 'Application Support', 'Code', 'User', 'mcp.json');
  }
  if (os === 'win32') {
    const appData = process.env.APPDATA || join(homedir(), 'AppData', 'Roaming');
    return join(appData, 'Code', 'User', 'mcp.json');
  }
  return join(homedir(), '.config', 'Code', 'User', 'mcp.json');
}

/**
 * Global (cross-project) agent config locations — same on every platform except
 * where the client itself follows OS conventions (VS Code, Claude Desktop).
 */
function globalConfigFiles() {
  return [
    claudeDesktopConfigPath(),
    // Cursor: global config applies to every project, distinct from the
    // per-project .cursor/mcp.json already in PROJECT_CONFIG_FILES.
    join(homedir(), '.cursor', 'mcp.json'),
    // Windsurf (Codeium) global MCP config.
    join(homedir(), '.codeium', 'windsurf', 'mcp_config.json'),
    vscodeGlobalConfigPath(),
  ];
}

/**
 * @typedef {object} DiscoveredConfig
 * @property {string} file - Absolute or cwd-relative path of the config file.
 * @property {string[]} profiles - AWS_PROFILE values referenced.
 * @property {string[]} roleArns - Role ARNs referenced anywhere in the file.
 * @property {Array<{file: string, keyIdSuffix: string}>} hardcodedKeys
 * @property {string[]} servers - MCP server names that reference AWS.
 */

/**
 * Scan one config file for AWS references.
 * @param {string} file
 * @returns {DiscoveredConfig|null} null when the file is absent or unreadable.
 */
export function scanConfigFile(file) {
  if (!existsSync(file)) return null;
  let raw;
  try {
    raw = readFileSync(file, 'utf8');
  } catch {
    return null;
  }

  const profiles = new Set();
  const roleArns = new Set(raw.match(ROLE_ARN_RE) || []);
  const hardcodedKeys = [];
  for (const m of raw.match(ACCESS_KEY_RE) || []) {
    hardcodedKeys.push({ file, keyIdSuffix: m.slice(-4) });
  }

  const servers = new Set();
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = null; // still return regex-level findings for non-JSON or broken files
  }

  if (parsed && typeof parsed === 'object') {
    // MCP client configs: { mcpServers: { name: { command, args, env } } }
    // Claude Code settings: { env: {...}, mcpServers?: {...} }
    const serverMap = parsed.mcpServers || parsed.servers || {};
    for (const [name, cfg] of Object.entries(serverMap)) {
      if (!cfg || typeof cfg !== 'object') continue;
      const env = cfg.env || {};
      const blob = JSON.stringify(cfg);
      let awsRelated = false;
      if (typeof env.AWS_PROFILE === 'string' && env.AWS_PROFILE) {
        profiles.add(env.AWS_PROFILE);
        awsRelated = true;
      }
      if (/\bAWS_|arn:aws:|amazonaws\.com/i.test(blob)) awsRelated = true;
      if (awsRelated) servers.add(name);
    }
    // Top-level env block (Claude Code settings.json)
    const topEnv = parsed.env || {};
    if (typeof topEnv.AWS_PROFILE === 'string' && topEnv.AWS_PROFILE)
      profiles.add(topEnv.AWS_PROFILE);
  }

  if (
    profiles.size === 0 &&
    roleArns.size === 0 &&
    hardcodedKeys.length === 0 &&
    servers.size === 0
  ) {
    return null;
  }
  return {
    file,
    profiles: [...profiles],
    roleArns: [...roleArns],
    hardcodedKeys,
    servers: [...servers],
  };
}

/**
 * Discover agent configs in a project directory + well-known global locations.
 * @param {string} cwd
 * @returns {{examined: string[], matches: DiscoveredConfig[]}}
 *   `examined` = config files that exist; `matches` = those referencing AWS.
 */
export function discoverAgentConfigs(cwd) {
  const candidates = [...PROJECT_CONFIG_FILES.map((f) => join(cwd, f)), ...globalConfigFiles()];
  const examined = [];
  const matches = [];
  for (const file of candidates) {
    if (!existsSync(file)) continue;
    examined.push(file);
    const found = scanConfigFile(file);
    if (found) matches.push(found);
  }
  return { examined, matches };
}
