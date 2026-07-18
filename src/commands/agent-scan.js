import { basename } from 'node:path';
import { discoverAgentConfigs } from '../agent-scan/discovery.js';
import {
  analyzeGuardrails,
  analyzePolicy,
  computeGrade,
  dedupeFindings,
} from '../agent-scan/engine.js';
import { printBlastRadius } from '../agent-scan/report.js';
import { toSarif } from '../agent-scan/sarif.js';
import { apiPost, getApiKey, readFileSafe } from '../utils.js';

// __CLI_VERSION__ is replaced at build time by esbuild define
const VERSION = typeof __CLI_VERSION__ !== 'undefined' ? __CLI_VERSION__ : '0.0.0';

const HELP = `
Usage: shieldly agent-scan [options]

Show the blast radius of an AI agent's AWS credentials: what it could
destroy, exfiltrate, or escalate to. Runs fully offline — nothing leaves
your machine.

Input (first match wins; defaults to auto-discovery in the current directory):
  --policy-file <path>   Analyze an IAM policy JSON file
  --role-arn <arn>       Fetch + analyze a role's attached and inline policies
                         (uses your local AWS credentials, read-only IAM calls)
  --profile <name>       Resolve an AWS profile's identity and analyze it
                         (with --role-arn: use this profile's credentials)
  --cfn-file <path>      Scan a synthesized CloudFormation template (e.g.
                         cdk.out/*.template.json) for agent-like resources
                         (Bedrock agents, ECS task definitions, Lambda
                         functions) and analyze their in-template IAM role

Output:
  --format <fmt>         table | json | sarif  (default: table)
  --json                 Shorthand for --format json
  --sarif                Shorthand for --format sarif (SARIF 2.1.0, for the
                         GitHub Security tab)
  -h, --help             Show this help

Enforcement & remediation:
  --budget <file>        Permission-budget file (shieldly.policy.yml) declaring
                         the max allowed severity/categories; non-zero exit on
                         violation (CI enforcement)
  --fix                  With --policy-file: print a tightened policy JSON
                         (wildcard statements marked REVIEW, explicit deny
                         guardrails for destructive/escalation actions).
                         Review before applying.
  --ignore <rule-id>     Suppress a rule (repeatable), e.g. --ignore BR-DATA-S3
  --upload               Upload the scan to your Shieldly account (Builder plan
                         or above): builds a per-identity blast-radius history,
                         diffs against the last scan, alerts on new CRITICALs.
                         Requires SHIELDLY_API_KEY or --api-key.

Auto-discovery scans for agent configs — project-level (.mcp.json, mcp.json,
.claude/settings.json, .cursor/mcp.json, .vscode/mcp.json) and global/cross-project
(Claude Desktop, Cursor, Windsurf, VS Code user profile) — and analyzes any AWS
profiles, role ARNs, or hardcoded keys they reference.

Exit codes: 1 when any CRITICAL or HIGH finding exists (CI-friendly), else 0.

Examples:
  shieldly agent-scan --policy-file agent-policy.json
  shieldly agent-scan --role-arn arn:aws:iam::123456789012:role/my-agent
  shieldly agent-scan --profile agent-profile
  shieldly agent-scan --cfn-file cdk.out/MyStack.template.json
  shieldly agent-scan                      # auto-discover agent configs in cwd
  shieldly agent-scan --sarif > results.sarif
`;

export async function agentScan(args) {
  if (args.includes('-h') || args.includes('--help')) {
    console.log(HELP);
    return;
  }

  const policyIdx = args.indexOf('--policy-file');
  const roleIdx = args.indexOf('--role-arn');
  const profileIdx = args.indexOf('--profile');
  const cfnIdx = args.indexOf('--cfn-file');
  const fmtIdx = args.indexOf('--format');

  let format = fmtIdx !== -1 ? args[fmtIdx + 1] : 'table';
  if (args.includes('--json')) format = 'json';
  if (args.includes('--sarif')) format = 'sarif';
  if (!['table', 'json', 'sarif'].includes(format)) {
    console.error(`Error: invalid --format "${format}". Use: table | json | sarif`);
    process.exit(1);
  }

  const policyFile = policyIdx !== -1 ? args[policyIdx + 1] : null;
  const roleArn = roleIdx !== -1 ? args[roleIdx + 1] : null;
  const profile = profileIdx !== -1 ? args[profileIdx + 1] : null;
  const cfnFile = cfnIdx !== -1 ? args[cfnIdx + 1] : null;

  const budgetIdx = args.indexOf('--budget');
  const budgetFile = budgetIdx !== -1 ? args[budgetIdx + 1] : null;
  const wantFix = args.includes('--fix');
  const wantUpload = args.includes('--upload');
  const keyIdx = args.indexOf('--api-key');
  const apiKey = getApiKey(keyIdx !== -1 ? args[keyIdx + 1] : null);
  if (wantUpload && !apiKey) {
    console.error(
      'Error: --upload requires an API key. Set SHIELDLY_API_KEY or pass --api-key.\n' +
        '  Get an API key (Builder plan or above): https://www.shieldly.io/app/api'
    );
    process.exit(1);
  }
  const ignoredRules = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--ignore' && args[i + 1]) ignoredRules.push(args[i + 1]);
  }
  if (wantFix && !policyFile) {
    console.error('Error: --fix requires --policy-file (static analysis of a policy document)');
    process.exit(1);
  }

  const quiet = format !== 'table';
  /** @type {import('../agent-scan/engine.js').Finding[]} */
  let findings = [];
  /** @type {string[]} */
  const sources = [];
  /** @type {object|null} */
  let parsedPolicy = null;

  try {
    if (policyFile) {
      const content = readFileSafe(policyFile);
      let policy;
      try {
        policy = JSON.parse(content);
      } catch {
        console.error('Error: --policy-file must be valid JSON');
        process.exit(1);
      }
      parsedPolicy = policy;
      const label = basename(policyFile);
      sources.push(label);
      findings.push(...analyzePolicy(policy, label));
    } else if (cfnFile) {
      const content = readFileSafe(cfnFile);
      let template;
      try {
        template = JSON.parse(content);
      } catch {
        console.error(
          'Error: --cfn-file must be valid JSON (a synthesized CloudFormation template)'
        );
        process.exit(1);
      }
      const { scanCloudFormationTemplate } = await import('../agent-scan/cfn.js');
      const agents = scanCloudFormationTemplate(template);
      if (agents.length === 0) {
        console.error(
          'No agent-like resources (AWS::Bedrock::Agent, AWS::ECS::TaskDefinition, ' +
            'AWS::Lambda::Function) with an in-template IAM role found in this template.\n' +
            "Roles defined in a different stack or referenced by literal ARN can't be " +
            'resolved offline — analyze the deployed role directly with --role-arn instead.'
        );
        process.exit(1);
      }
      for (const agent of agents) {
        const label = `${agent.logicalId} (${agent.kind})`;
        sources.push(label);
        findings.push(...agent.findings);
        if (!quiet) {
          console.log(`Found ${label} — this template deploys an agent with this blast radius.`);
          if (agent.managedPolicyArns.length > 0) {
            console.log(
              `  ${agent.managedPolicyArns.length} attached managed policy ARN(s) not expanded offline: ` +
                agent.managedPolicyArns.join(', ')
            );
          }
        }
      }
    } else if (roleArn) {
      if (!quiet) console.log(`Fetching policies for ${roleArn}…`);
      const { fetchRolePolicies } = await import('../agent-scan/aws.js');
      const identity = await fetchRolePolicies(roleArn, profile || undefined);
      sources.push(identity.label);
      for (const p of identity.policies) {
        findings.push(...analyzePolicy(p.document, `${identity.label} · ${p.name}`));
      }
      findings.push(
        ...analyzeGuardrails({
          hasPermissionBoundary: identity.hasPermissionBoundary,
          identityLabel: identity.label,
        })
      );
    } else if (profile) {
      if (!quiet) console.log(`Resolving AWS profile "${profile}"…`);
      const { resolveProfile } = await import('../agent-scan/aws.js');
      const identity = await resolveProfile(profile);
      sources.push(identity.label);
      for (const p of identity.policies) {
        findings.push(...analyzePolicy(p.document, `${identity.label} · ${p.name}`));
      }
      findings.push(
        ...analyzeGuardrails({
          hasPermissionBoundary: identity.hasPermissionBoundary,
          identityLabel: identity.label,
        })
      );
    } else {
      // Auto-discovery: scan agent configs in cwd + well-known locations.
      const { examined, matches: configs } = discoverAgentConfigs(process.cwd());
      if (examined.length === 0) {
        console.error(
          'No agent configs found (.mcp.json, mcp.json, .claude/settings.json, Claude Desktop).\n' +
            'Point at an input explicitly:\n' +
            '  shieldly agent-scan --policy-file <policy.json>\n' +
            '  shieldly agent-scan --role-arn <arn>\n' +
            '  shieldly agent-scan --profile <name>'
        );
        process.exit(1);
      }
      if (configs.length === 0) {
        // Configs exist but none reference AWS credentials — a clean pass.
        sources.push(...examined);
        if (!quiet) {
          console.log(
            `Examined ${examined.length} agent config(s) — no AWS credentials or role references found.`
          );
        }
      }

      const hardcodedKeys = [];
      const profilesToScan = new Map(); // profile -> config file label
      const rolesToScan = new Map(); // arn -> config file label

      for (const cfg of configs) {
        sources.push(cfg.file);
        if (!quiet) {
          const what = [
            cfg.servers.length && `${cfg.servers.length} AWS-related MCP server(s)`,
            cfg.profiles.length && `profiles: ${cfg.profiles.join(', ')}`,
            cfg.roleArns.length && `${cfg.roleArns.length} role ARN(s)`,
            cfg.hardcodedKeys.length && `${cfg.hardcodedKeys.length} hardcoded key(s)`,
          ]
            .filter(Boolean)
            .join('; ');
          console.log(`Discovered ${cfg.file} — ${what}`);
        }
        hardcodedKeys.push(...cfg.hardcodedKeys);
        for (const p of cfg.profiles) profilesToScan.set(p, cfg.file);
        for (const arn of cfg.roleArns) rolesToScan.set(arn, cfg.file);
      }

      findings.push(...analyzeGuardrails({ hardcodedKeys }));

      for (const [prof] of profilesToScan) {
        if (!quiet) console.log(`Resolving AWS profile "${prof}"…`);
        try {
          const { resolveProfile } = await import('../agent-scan/aws.js');
          const identity = await resolveProfile(prof);
          sources.push(identity.label);
          for (const p of identity.policies) {
            findings.push(...analyzePolicy(p.document, `${identity.label} · ${p.name}`));
          }
          findings.push(
            ...analyzeGuardrails({
              hasPermissionBoundary: identity.hasPermissionBoundary,
              identityLabel: identity.label,
            })
          );
        } catch (err) {
          if (!quiet) console.log(`  Skipped profile "${prof}": ${err.message}`);
        }
      }

      for (const [arn] of rolesToScan) {
        if (!quiet) console.log(`Fetching policies for ${arn}…`);
        try {
          const { fetchRolePolicies } = await import('../agent-scan/aws.js');
          const identity = await fetchRolePolicies(arn);
          sources.push(identity.label);
          for (const p of identity.policies) {
            findings.push(...analyzePolicy(p.document, `${identity.label} · ${p.name}`));
          }
          findings.push(
            ...analyzeGuardrails({
              hasPermissionBoundary: identity.hasPermissionBoundary,
              identityLabel: identity.label,
            })
          );
        } catch (err) {
          if (!quiet) console.log(`  Skipped role ${arn}: ${err.message}`);
        }
      }
    }
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  findings = dedupeFindings(findings);
  if (ignoredRules.length > 0) {
    findings = findings.filter((f) => !ignoredRules.includes(f.ruleId));
  }
  const grade = computeGrade(findings);
  const report = { grade, findings, sources };

  // --fix: print the tightened policy to stdout (report goes to stderr context
  // via table format only), so `--fix > tightened.json` just works.
  if (wantFix) {
    const { buildFixedPolicy } = await import('../agent-scan/fix.js');
    const { fixed, denied, reviewCount } = buildFixedPolicy(parsedPolicy);
    console.log(JSON.stringify(fixed, null, 2));
    console.error(
      `\nLeast-privilege draft (static analysis — REVIEW BEFORE APPLYING):\n` +
        `  ${denied.length} dangerous action pattern(s) denied via ShieldlyAgentGuardrails statement\n` +
        `  ${reviewCount} wildcard statement(s) marked with REVIEW Sid — tighten manually\n` +
        `  Validate in a non-production account first.`
    );
    return;
  }

  if (format === 'json') {
    console.log(JSON.stringify(report, null, 2));
  } else if (format === 'sarif') {
    console.log(JSON.stringify(toSarif(findings, { version: VERSION }), null, 2));
  } else {
    printBlastRadius(report);
  }

  // --budget: declared permission budget decides the exit code.
  if (budgetFile) {
    const { evaluateBudget, loadBudget } = await import('../agent-scan/budget.js');
    let result;
    try {
      result = evaluateBudget(findings, loadBudget(budgetFile));
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(1);
    }
    if (!result.pass) {
      console.error(`Budget violations (${result.violations.length}) — ${budgetFile}:`);
      for (const v of result.violations) console.error(`  ✗ ${v}`);
      process.exit(1);
    }
    if (!quiet) console.log(`Budget check passed (${budgetFile})`);
    return;
  }

  if (wantUpload) {
    const identityLabel = sources[0] || 'agent';
    try {
      const res = await apiPost(
        '/v1/agent-scan',
        {
          identityLabel,
          grade,
          sources,
          findings: findings.map((f) => ({
            ruleId: f.ruleId,
            category: f.category,
            severity: f.severity,
            title: f.title,
            source: f.source,
          })),
        },
        apiKey
      );
      if (!quiet) {
        const added = res.diff?.added?.length ?? 0;
        const removed = res.diff?.removed?.length ?? 0;
        console.log(
          res.isFirstScan
            ? `Uploaded — first scan recorded for "${identityLabel}". View: https://www.shieldly.io/app/agents`
            : `Uploaded — ${added} new, ${removed} resolved since last scan. View: https://www.shieldly.io/app/agents`
        );
        if (res.diff?.newCriticalCount > 0) {
          console.log(`  ⚠ ${res.diff.newCriticalCount} NEW critical finding(s) since last scan.`);
        }
      }
    } catch (err) {
      console.error(`Upload failed: ${err.message}`);
      process.exit(1);
    }
  }

  const failing = findings.some((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  if (failing) process.exit(1);
}
