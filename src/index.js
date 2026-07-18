import { agentScan } from './commands/agent-scan.js';
import { analyzeCF } from './commands/analyze-cf.js';
import { analyzeIAM } from './commands/analyze-iam.js';
import { apiKeys } from './commands/api-keys.js';
import { completion } from './commands/completion.js';

const BOLD = '\x1b[1m';
const CYAN = '\x1b[36m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

// __CLI_VERSION__ is injected at build time by esbuild define (see build.js)
const VERSION = typeof __CLI_VERSION__ !== 'undefined' ? __CLI_VERSION__ : '0.0.0';

const HELP = `
${BOLD}shieldly${RESET} — AI-Powered Security Analysis for AWS

${BOLD}Usage:${RESET}
  shieldly <command> [args] [options]

${BOLD}Commands:${RESET}
  ${CYAN}analyze-iam${RESET}  <policy-file>          Analyze an IAM policy for security issues
  ${CYAN}analyze-cf${RESET}   <template-file-or-dir> Analyze a CloudFormation template or CDK output directory
  ${CYAN}agent-scan${RESET}   [options]              Blast radius of an AI agent's AWS credentials (offline)
  ${CYAN}api-keys${RESET}     list|create|revoke     Manage API keys
  ${CYAN}completion${RESET}   bash|zsh|install       Generate shell completion

${BOLD}Global Options:${RESET}
  --api-key <key>   API key (or set SHIELDLY_API_KEY env var)
  --version         Show version
  -h, --help        Show this help

${BOLD}Authentication:${RESET}
  Set your API key via env var:   export SHIELDLY_API_KEY=sk_...
  Get an API key (Builder plan or above) at: ${CYAN}https://www.shieldly.io/app/api${RESET}

${BOLD}Examples:${RESET}
  ${DIM}# Analyze an IAM policy or CF template (no API key needed — demo mode)${RESET}
  shieldly analyze-iam policy.json

  ${DIM}# Analyze a single CloudFormation template${RESET}
  shieldly analyze-cf template.json

  ${DIM}# Scan all CDK stacks after synthesis (reads manifest.json — current stacks only)${RESET}
  cdk synth && shieldly analyze-cf cdk.out/

  ${DIM}# List API keys${RESET}
  shieldly api-keys list

  ${DIM}# Use in CI${RESET}
  SHIELDLY_API_KEY=\${{ secrets.SHIELDLY_API_KEY }} shieldly analyze-iam policy.json
`;

async function main() {
  const [, , command, ...args] = process.argv;

  if (!command || command === '-h' || command === '--help') {
    console.log(HELP);
    process.exit(0);
  }

  if (command === '--version' || command === '-v') {
    console.log(VERSION);
    process.exit(0);
  }

  switch (command) {
    case 'agent-scan':
      await agentScan(args);
      break;
    case 'analyze-iam':
      await analyzeIAM(args);
      break;
    case 'analyze-cf':
      await analyzeCF(args);
      break;
    case 'api-keys':
      await apiKeys(args);
      break;
    case 'completion':
      await completion(args);
      break;
    default:
      console.error(`Unknown command: ${command}`);
      console.log(`Run ${BOLD}shieldly --help${RESET} for usage`);
      process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err.message);
  process.exit(1);
});
