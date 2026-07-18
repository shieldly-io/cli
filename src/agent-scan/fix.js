/**
 * Least-privilege generator (v1, static analysis) — `agent-scan --fix`.
 *
 * Emits a tightened copy of the input policy:
 *  1. Wildcard statements (Action "*", service:*, Resource "*") keep working
 *     but get a `REVIEW-` Sid prefix so they're easy to grep and tighten.
 *  2. A deny-guardrail statement is appended covering every DESTRUCTIVE and
 *     ESCALATION action the scan matched — an explicit Deny always wins over
 *     Allow, so this immediately caps the blast radius without breaking
 *     read paths.
 *
 * Output is labeled "review before applying" — static analysis cannot know
 * which permissions the agent actually uses.
 */

import { globsIntersect } from './engine.js';
import { ACTION_RULES } from './rules.js';

const GUARDRAIL_CATEGORIES = new Set(['DESTRUCTIVE', 'ESCALATION']);

function toArray(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

/**
 * Build a tightened policy from the original + scan findings.
 * @param {object} policy - Parsed original policy document.
 * @returns {{fixed: object, denied: string[], reviewCount: number}}
 */
export function buildFixedPolicy(policy) {
  const statements = toArray(policy?.Statement);

  // Collect every dangerous rule action the policy actually grants — those
  // become the explicit deny list.
  const denied = new Set();
  for (const st of statements) {
    if (st.Effect !== 'Allow') continue;
    const actions = toArray(st.Action).map(String);
    for (const rule of ACTION_RULES) {
      if (!GUARDRAIL_CATEGORIES.has(rule.category)) continue;
      for (const ruleAction of rule.actions) {
        if (actions.some((granted) => globsIntersect(granted, ruleAction))) {
          denied.add(ruleAction);
        }
      }
    }
  }

  let reviewCount = 0;
  const fixedStatements = statements.map((st, idx) => {
    const copy = { ...st };
    if (st.Effect !== 'Allow') return copy;
    const actions = toArray(st.Action).map(String);
    const resources = toArray(st.Resource).map(String);
    const wildcardAction = actions.includes('*') || actions.some((a) => a.endsWith(':*'));
    const wildcardResource = resources.includes('*');
    if (wildcardAction || wildcardResource) {
      reviewCount++;
      const baseSid = st.Sid || `Statement${idx + 1}`;
      copy.Sid = baseSid.startsWith('REVIEW') ? baseSid : `REVIEW${baseSid}`;
    }
    return copy;
  });

  const fixed = {
    ...policy,
    Statement: fixedStatements,
  };

  if (denied.size > 0) {
    fixed.Statement = [
      ...fixedStatements,
      {
        Sid: 'ShieldlyAgentGuardrails',
        Effect: 'Deny',
        Action: [...denied].sort(),
        Resource: '*',
      },
    ];
  }

  return { fixed, denied: [...denied].sort(), reviewCount };
}
