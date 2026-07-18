# Changelog

All notable changes to `@shieldly/cli` are documented here.

## Unreleased

- New install channels: Docker image (`ghcr.io/shieldly-io/cli`, built from the
  committed `dist/cli.cjs` bundle) and the existing Homebrew tap are now both
  documented in the README. No CLI code changes.

## 1.3.1

- Fix: statements with a `Principal` (role trust policies, resource policies)
  are no longer analyzed with identity-policy rules. Previously a well-scoped
  trust policy (service principal + `aws:SourceAccount`/`aws:SourceArn`
  conditions) was wrongly graded CRITICAL (`BR-ESC-ASSUME-STAR`) because its
  `sts:AssumeRole` has no `Resource` element.
- New trust-policy checks: `BR-TRUST-OPEN-PRINCIPAL` (CRITICAL — `Principal`
  `"*"` with no `Condition` lets any AWS identity assume the role) and
  `BR-TRUST-SERVICE-NO-SCOPE` (MEDIUM — service principal without
  `aws:SourceAccount`/`aws:SourceArn` scoping, the confused-deputy setup).

## 1.3.0

- `agent-scan --cfn-file <path>`: scan a synthesized CloudFormation template for
  agent-like resources (`AWS::Bedrock::Agent`, `AWS::ECS::TaskDefinition`,
  `AWS::Lambda::Function`) and analyze their in-template IAM role's inline
  policies. Flags "this template deploys an agent with this blast radius."
  Managed-policy ARNs attached to the role are reported but not expanded
  (their document isn't in the template) — use `--role-arn` against the
  deployed role for the full picture.
- Auto-discovery now also finds global (cross-project) agent configs: Cursor
  (`~/.cursor/mcp.json`), Windsurf (`~/.codeium/windsurf/mcp_config.json`), and
  VS Code's user-profile `mcp.json`, in addition to the existing project-level
  paths and Claude Desktop.

## 1.2.0

- `agent-scan --upload`: send scan findings to your Shieldly account (Builder
  plan+) — builds a per-agent-identity blast-radius history, diffs each scan
  against the last one, and alerts on newly-introduced CRITICAL findings.
  Never uploads the raw policy or config, only rule-level finding metadata.
- Dashboard agent inventory at `/app/agents`.

## 1.1.0

- **`agent-scan`** — new command: the blast radius of an AI agent's AWS
  credentials. Runs fully offline.
  - Input: `--policy-file`, `--role-arn`, `--profile`, or auto-discovery of
    `.mcp.json` / Claude Code / Claude Desktop configs in the current project.
  - Output: `--format table|json|sarif` (SARIF 2.1.0, validated against the
    schema — findings can land in the GitHub Security tab).
  - `--fix`: prints a tightened policy JSON (wildcard statements marked for
    review, explicit deny guardrails for destructive/escalation actions).
  - `--budget <file>`: declare a permission budget (`shieldly.policy.yml`) and
    fail CI when a scan violates it.
  - `--ignore <rule-id>`: suppress a rule (repeatable), for false positives.

## 1.0.5 and earlier

- `analyze-iam`, `analyze-cf`, `api-keys`, `completion` — see
  [shieldly.io/docs/cli](https://www.shieldly.io/docs/cli).
