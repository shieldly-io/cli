/**
 * Terminal Blast-Radius Report — findings grouped by category, graded overall.
 * Follows the ANSI conventions of printResults in ../utils.js.
 */

import { SEVERITY_RANK } from './engine.js';
import { CATEGORY_ORDER } from './rules.js';

const SEV_COLOR = {
  CRITICAL: '\x1b[31m',
  HIGH: '\x1b[33m',
  MEDIUM: '\x1b[36m',
  LOW: '\x1b[32m',
};
const GRADE_COLOR = {
  CRITICAL: '\x1b[41m\x1b[97m', // white on red
  HIGH: '\x1b[31m',
  MODERATE: '\x1b[33m',
  LOW: '\x1b[32m',
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const CYAN = '\x1b[36m';

const CATEGORY_LABEL = {
  ESCALATION: 'Privilege escalation',
  DESTRUCTIVE: 'Destructive actions',
  WILDCARD: 'Wildcard grants',
  DATA_ACCESS: 'Data access',
  COST_RISK: 'Cost risk',
  NO_GUARDRAILS: 'Missing guardrails',
};

/**
 * @param {object} report
 * @param {string} report.grade
 * @param {import('./engine.js').Finding[]} report.findings
 * @param {string[]} report.sources - Labels of everything that was analyzed.
 */
export function printBlastRadius(report) {
  const { grade, findings, sources } = report;

  console.log('');
  console.log(`${BOLD}AI-Powered Security Analysis — Shieldly Agent Blast-Radius${RESET}`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(
    `  ${BOLD}Blast-Radius Grade:${RESET}  ${GRADE_COLOR[grade] || ''} ${grade} ${RESET}`
  );
  console.log(`  ${BOLD}Analyzed:${RESET}  ${sources.length ? sources.join(', ') : '(nothing)'}`);
  console.log(`  ${BOLD}Findings:${RESET}  ${findings.length}`);
  console.log('');

  if (findings.length === 0) {
    console.log(`  ${CYAN}[PASS] No blast-radius findings${RESET}`);
    console.log('');
    return;
  }

  for (const category of CATEGORY_ORDER) {
    const group = findings
      .filter((f) => f.category === category)
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
    if (group.length === 0) continue;

    console.log(`${BOLD}${CATEGORY_LABEL[category] || category} (${group.length})${RESET}`);
    for (const f of group) {
      const col = SEV_COLOR[f.severity] || '';
      console.log(
        `\n  ${col}[${f.severity}]${RESET} ${BOLD}${f.title}${RESET} ${DIM}(${f.ruleId})${RESET}`
      );
      console.log(`         ${DIM}${f.description}${RESET}`);
      if (f.matchedActions.length > 0) {
        console.log(`         ${DIM}Granted: ${f.matchedActions.join(', ')}${RESET}`);
      }
      const res = (f.resources || []).filter((r) => r !== '*');
      if (res.length > 0) {
        console.log(
          `         ${DIM}Resources: ${res.slice(0, 5).join(', ')}${res.length > 5 ? ` (+${res.length - 5} more)` : ''}${RESET}`
        );
      }
      console.log(`         ${DIM}Source: ${f.source}${RESET}`);
      console.log(`  ${CYAN}Fix:${RESET}  ${f.remediation}`);
    }
    console.log('');
  }
}
