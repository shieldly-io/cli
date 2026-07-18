/**
 * Permission-budget enforcement — `agent-scan --budget shieldly.policy.yml`.
 *
 * The budget file declares the maximum blast radius a repo allows its agents.
 * CI fails (non-zero exit) when a scan exceeds it.
 *
 * Budget file schema (YAML or JSON):
 *
 *   version: 1
 *   max-severity: MEDIUM        # highest severity allowed to pass (CRITICAL|HIGH|MEDIUM|LOW|none)
 *   deny-categories:            # categories that always fail, regardless of severity
 *     - ESCALATION
 *   ignore-rules:               # rule IDs suppressed entirely (false positives)
 *     - BR-DATA-S3
 *   max-findings: 50            # optional cap on total (non-ignored) findings
 */

import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { SEVERITY_RANK } from './engine.js';

/**
 * @typedef {object} Budget
 * @property {number} version
 * @property {string|null} maxSeverity
 * @property {string[]} denyCategories
 * @property {string[]} ignoreRules
 * @property {number|null} maxFindings
 */

/**
 * Load and normalize a budget file.
 * @param {string} file
 * @returns {Budget}
 */
export function loadBudget(file) {
  let raw;
  try {
    raw = readFileSync(file, 'utf8');
  } catch {
    throw new Error(`Budget file not found: ${file}`);
  }
  let doc;
  try {
    doc = parseYaml(raw);
  } catch (err) {
    throw new Error(`Budget file is not valid YAML/JSON: ${err.message}`);
  }
  if (!doc || typeof doc !== 'object') throw new Error('Budget file must be a YAML/JSON object');

  const maxSeverity = String(doc['max-severity'] ?? doc.maxSeverity ?? 'none').toUpperCase();
  if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'].includes(maxSeverity)) {
    throw new Error(`Invalid max-severity "${maxSeverity}". Use: CRITICAL|HIGH|MEDIUM|LOW|none`);
  }

  return {
    version: Number(doc.version) || 1,
    maxSeverity: maxSeverity === 'NONE' ? null : maxSeverity,
    denyCategories: (doc['deny-categories'] ?? doc.denyCategories ?? []).map((c) =>
      String(c).toUpperCase()
    ),
    ignoreRules: (doc['ignore-rules'] ?? doc.ignoreRules ?? []).map(String),
    maxFindings:
      (doc['max-findings'] ?? doc.maxFindings)
        ? Number(doc['max-findings'] ?? doc.maxFindings)
        : null,
  };
}

/**
 * Evaluate findings against a budget.
 * @param {import('./engine.js').Finding[]} findings
 * @param {Budget} budget
 * @returns {{pass: boolean, violations: string[], considered: import('./engine.js').Finding[]}}
 */
export function evaluateBudget(findings, budget) {
  const considered = findings.filter((f) => !budget.ignoreRules.includes(f.ruleId));
  const violations = [];

  if (budget.maxSeverity) {
    const cap = SEVERITY_RANK[budget.maxSeverity];
    for (const f of considered) {
      if (SEVERITY_RANK[f.severity] > cap) {
        violations.push(
          `[${f.severity}] ${f.ruleId} exceeds max-severity ${budget.maxSeverity}: ${f.title} (${f.source})`
        );
      }
    }
  }

  for (const f of considered) {
    if (budget.denyCategories.includes(f.category)) {
      violations.push(
        `[${f.severity}] ${f.ruleId} in denied category ${f.category}: ${f.title} (${f.source})`
      );
    }
  }

  if (budget.maxFindings !== null && considered.length > budget.maxFindings) {
    violations.push(`${considered.length} findings exceed max-findings ${budget.maxFindings}`);
  }

  return { pass: violations.length === 0, violations, considered };
}
