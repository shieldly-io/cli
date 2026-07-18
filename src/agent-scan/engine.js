/**
 * Blast-radius analysis engine — pure, offline, no network.
 *
 * Takes parsed IAM policy documents, runs the data-driven rules table over
 * them, returns categorized findings + an overall grade.
 */

import { ACTION_RULES, GUARDRAIL_RULES, STRUCTURAL_RULES } from './rules.js';

const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function toArray(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

/**
 * Do two glob patterns (with `*` wildcards) match at least one common string?
 * Used to test whether a granted action pattern (e.g. "s3:*") covers a rule
 * pattern (e.g. "s3:DeleteObject") — in either direction — without expanding
 * the full AWS action list. Case-insensitive, as IAM actions are.
 */
export function globsIntersect(a, b) {
  const s1 = a.toLowerCase();
  const s2 = b.toLowerCase();
  const memo = new Map();
  function go(i, j) {
    const key = `${i},${j}`;
    if (memo.has(key)) return memo.get(key);
    let res;
    if (i === s1.length && j === s2.length) {
      res = true;
    } else if (i < s1.length && s1[i] === '*') {
      // '*' consumes zero chars of its own string, or absorbs one char of the other
      res = go(i + 1, j) || (j < s2.length && go(i, j + 1));
    } else if (j < s2.length && s2[j] === '*') {
      res = go(i, j + 1) || (i < s1.length && go(i + 1, j));
    } else if (i < s1.length && j < s2.length && s1[i] === s2[j]) {
      res = go(i + 1, j + 1);
    } else {
      res = false;
    }
    memo.set(key, res);
    return res;
  }
  return go(0, 0);
}

function hasWildcardResource(resources) {
  return resources.some((r) => r === '*');
}

/**
 * @typedef {object} Finding
 * @property {string} ruleId
 * @property {string} category
 * @property {'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'} severity
 * @property {string} title
 * @property {string} description
 * @property {string} remediation
 * @property {string} source - Which policy/config the finding came from.
 * @property {string[]} matchedActions - Granted actions that triggered the rule.
 * @property {string[]} resources - Resources in the matching statement.
 */

/**
 * Analyze one policy document.
 * @param {object} policy - Parsed IAM policy JSON.
 * @param {string} source - Label for where this policy came from (file, policy name).
 * @returns {Finding[]}
 */
export function analyzePolicy(policy, source) {
  /** @type {Finding[]} */
  const findings = [];
  const statements = toArray(policy?.Statement);

  statements.forEach((st, idx) => {
    if (st.Effect !== 'Allow') return;
    const actions = toArray(st.Action).map(String);
    const notActions = toArray(st.NotAction).map(String);
    const resources = toArray(st.Resource).map(String);
    const hasCondition = st.Condition && Object.keys(st.Condition).length > 0;
    const wildRes = hasWildcardResource(resources) || resources.length === 0;
    const where = `${source} · statement ${idx + 1}`;

    // Statements with a Principal are resource-based (trust policies, bucket
    // policies, …). Identity-policy rules don't apply: a trust policy's
    // sts:AssumeRole has no Resource and grants assumption OF this role, not
    // BY it. Run the trust-specific checks instead.
    if (st.Principal !== undefined || st.NotPrincipal !== undefined) {
      findings.push(...analyzeTrustStatement(st, where, hasCondition));
      return;
    }

    // Structural WILDCARD rules
    if (actions.includes('*')) {
      findings.push(structural(STRUCTURAL_RULES.ACTION_STAR, where, ['*'], resources));
    }
    for (const a of actions) {
      if (a !== '*' && a.endsWith(':*')) {
        const rule = STRUCTURAL_RULES.SERVICE_STAR;
        findings.push({
          ...structural(rule, where, [a], resources),
          title: `${rule.title} ("${a}")`,
        });
      }
    }
    if (hasWildcardResource(resources)) {
      findings.push(structural(STRUCTURAL_RULES.RESOURCE_STAR, where, actions, resources));
    }
    if (notActions.length > 0) {
      findings.push(structural(STRUCTURAL_RULES.NOTACTION_ALLOW, where, notActions, resources));
    }

    // Action-category rules
    for (const rule of ACTION_RULES) {
      if (rule.requiresNoCondition && hasCondition) continue;
      if (rule.requiresWildcardResource && !wildRes) continue;
      const matched = [];
      for (const granted of actions) {
        if (rule.actions.some((p) => globsIntersect(granted, p))) matched.push(granted);
      }
      if (matched.length === 0) continue;
      const severity =
        wildRes && rule.severityOnWildcardResource
          ? rule.severityOnWildcardResource
          : rule.severity;
      findings.push({
        ruleId: rule.id,
        category: rule.category,
        severity,
        title: rule.title,
        description: rule.description,
        remediation: rule.remediation,
        source: where,
        matchedActions: [...new Set(matched)],
        resources,
      });
    }
  });

  return findings;
}

/**
 * Trust-policy / resource-policy statement checks (statement has a Principal).
 * @param {object} st - The policy statement.
 * @param {string} where - Human-readable source label.
 * @param {boolean} hasCondition - Whether the statement carries a Condition.
 * @returns {Finding[]}
 */
function analyzeTrustStatement(st, where, hasCondition) {
  const findings = [];
  const p = st.Principal;
  const awsPrincipals = toArray(typeof p === 'object' && p !== null ? p.AWS : p).map(String);
  const servicePrincipals =
    typeof p === 'object' && p !== null ? toArray(p.Service).map(String) : [];
  const actions = toArray(st.Action).map(String);
  const isAssume = actions.some((a) => a === '*' || a.toLowerCase().startsWith('sts:assumerole'));

  if (isAssume && !hasCondition && (p === '*' || awsPrincipals.includes('*'))) {
    findings.push(structural(STRUCTURAL_RULES.TRUST_OPEN_PRINCIPAL, where, actions, ['*']));
  } else if (isAssume && !hasCondition && servicePrincipals.length > 0) {
    findings.push(
      structural(STRUCTURAL_RULES.TRUST_SERVICE_NO_SCOPE, where, actions, servicePrincipals)
    );
  }
  return findings;
}

function structural(rule, source, matchedActions, resources) {
  return {
    ruleId: rule.id,
    category: rule.category,
    severity: rule.severity,
    title: rule.title,
    description: rule.description,
    remediation: rule.remediation,
    source,
    matchedActions,
    resources,
  };
}

/**
 * Context-level guardrail findings.
 * @param {object} ctx
 * @param {Array<{file: string, keyIdSuffix: string}>} [ctx.hardcodedKeys] - Long-lived keys found in config files.
 * @param {boolean|null} [ctx.hasPermissionBoundary] - null = unknown (skip the check).
 * @returns {Finding[]}
 */
export function analyzeGuardrails(ctx) {
  const findings = [];
  for (const hk of ctx.hardcodedKeys || []) {
    const rule = GUARDRAIL_RULES.HARDCODED_KEY;
    findings.push({
      ruleId: rule.id,
      category: rule.category,
      severity: rule.severity,
      title: rule.title,
      description: `${rule.description} (key ending …${hk.keyIdSuffix})`,
      remediation: rule.remediation,
      source: hk.file,
      matchedActions: [],
      resources: [],
    });
  }
  if (ctx.hasPermissionBoundary === false) {
    const rule = GUARDRAIL_RULES.NO_BOUNDARY;
    findings.push({
      ruleId: rule.id,
      category: rule.category,
      severity: rule.severity,
      title: rule.title,
      description: rule.description,
      remediation: rule.remediation,
      source: ctx.identityLabel || 'agent identity',
      matchedActions: [],
      resources: [],
    });
  }
  return findings;
}

/**
 * Dedupe findings that fire on the same rule + source, keeping the higher severity.
 * @param {Finding[]} findings
 */
export function dedupeFindings(findings) {
  const byKey = new Map();
  for (const f of findings) {
    const key = `${f.ruleId}|${f.source}`;
    const prev = byKey.get(key);
    if (!prev || SEVERITY_RANK[f.severity] > SEVERITY_RANK[prev.severity]) byKey.set(key, f);
  }
  return [...byKey.values()];
}

/**
 * Overall blast-radius grade from findings.
 * @param {Finding[]} findings
 * @returns {'CRITICAL'|'HIGH'|'MODERATE'|'LOW'}
 */
export function computeGrade(findings) {
  let max = 0;
  for (const f of findings) max = Math.max(max, SEVERITY_RANK[f.severity] || 0);
  if (max >= 4) return 'CRITICAL';
  if (max === 3) return 'HIGH';
  if (max === 2) return 'MODERATE';
  return 'LOW';
}

export { SEVERITY_RANK };
