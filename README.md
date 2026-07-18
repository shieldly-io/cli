# @shieldly/cli

**AI-Powered Security Analysis for AWS — official CLI.**

Analyze AWS IAM policies and CloudFormation templates for security risks from
any terminal, shell script, or CI/CD pipeline. Powered by
[Shieldly](https://www.shieldly.io).

```bash
npm install -g @shieldly/cli
```

Also available via Homebrew and Docker (no Node required):

```bash
brew install shieldly-io/tap/shieldly
docker run --rm -v "$PWD":/work ghcr.io/shieldly-io/cli analyze-iam /work/policy.json
```

[▶ Watch a recorded terminal session](https://www.shieldly.io/docs/cli#demo) — wildcard policy
flagged, then a scoped one passing clean.

## Try it free — no account needed

Both `analyze-iam` and `analyze-cf` run in demo mode without an API key
(5 free analyses, no signup required):

```bash
shieldly analyze-iam policy.json
shieldly analyze-cf template.yaml
```

For higher limits and analysis history, create an account
([API keys require a Builder plan or above](https://www.shieldly.io/app/api)) and set your key:

```bash
export SHIELDLY_API_KEY=sk_live_...
shieldly analyze-cf template.yaml
```

Upgrade to a paid plan for higher daily limits, team access, and priority AI.

## Quick start

```bash
# Set your API key (get one free at https://www.shieldly.io/app/api)
export SHIELDLY_API_KEY=sk_live_...

# Analyze an IAM policy
shieldly analyze-iam policy.json

# Analyze a CloudFormation template
shieldly analyze-cf template.yaml

# Manage API keys
shieldly api-keys list
```

## Free tier

| Mode | Limit | Requires |
| --- | --- | --- |
| Demo (no key) | 5 analyses total | No account |
| Free account | 20 units/day | Free sign-up |
| Builder | 150 units/day | Paid plan |
| Pro | 300 units/day | Paid plan |
| Team | 600 units/day | Paid plan |

Analysis units depend on input size — a small IAM policy costs 1 unit;
large CloudFormation templates cost more. [Compare plans →](https://www.shieldly.io/#pricing)

## Commands

| Command | Description |
| --- | --- |
| `shieldly agent-scan [options]` | Blast radius of an AI agent's AWS credentials (offline) |
| `shieldly analyze-iam <policy-file>` | Analyze an IAM policy for security issues |
| `shieldly analyze-cf <template-file>` | Analyze a CloudFormation template |
| `shieldly api-keys list\|create\|revoke` | Manage API keys |
| `shieldly completion bash\|zsh\|install` | Shell completion |

## Agent blast-radius scan

See what your AI agents' AWS credentials could **destroy, exfiltrate, or
escalate to**. Runs fully offline — your config never leaves your machine, no
API key required.

```bash
# Scan an IAM policy file
shieldly agent-scan --policy-file agent-policy.json

# Fetch and scan a live role (uses your local AWS credentials, read-only)
shieldly agent-scan --role-arn arn:aws:iam::123456789012:role/my-agent

# Resolve an AWS profile's identity and scan it (users: includes group policies)
shieldly agent-scan --profile agent-profile

# Zero flags: auto-discover agent configs in the current directory
# (.mcp.json, mcp.json, .claude/settings.json, .cursor/.vscode mcp.json,
#  Claude Desktop config) and scan any AWS profiles / role ARNs / hardcoded
#  keys they reference
shieldly agent-scan
```

Findings are graded overall (CRITICAL / HIGH / MODERATE / LOW) and grouped into
six categories: privilege escalation, destructive actions, wildcard grants, data
access, cost risk, and missing guardrails. Hardcoded `AKIA…` keys in agent
configs are flagged CRITICAL.

**Output & remediation:**

```bash
shieldly agent-scan --policy-file p.json --json           # machine-readable
shieldly agent-scan --policy-file p.json --sarif > out.sarif  # GitHub Security tab
shieldly agent-scan --policy-file p.json --fix > tightened.json  # least-privilege draft
shieldly agent-scan --policy-file p.json --ignore BR-DATA-S3     # suppress a rule
```

**CI enforcement** — declare a permission budget and fail the build when an
agent's blast radius exceeds it:

```bash
shieldly agent-scan --policy-file agent-policy.json --budget shieldly.policy.yml
```

```yaml
# shieldly.policy.yml
version: 1
max-severity: MEDIUM       # CRITICAL | HIGH | MEDIUM | LOW | none
deny-categories:
  - ESCALATION             # always fail on privilege-escalation findings
ignore-rules: []           # accepted false positives, by rule ID
# max-findings: 50
```

Exit code is `1` on any CRITICAL/HIGH finding (or any budget violation), `0`
otherwise — drop it straight into CI. See
[`shieldly.policy.example.yml`](./shieldly.policy.example.yml).

## Global options

| Option | Description |
| --- | --- |
| `--api-key <key>` | API key (or set `SHIELDLY_API_KEY`) |
| `--version` | Show version |
| `-h`, `--help` | Show help |

## Use in CI

```yaml
- name: AI-Powered IAM Analysis
  run: |
    npm install -g @shieldly/cli
    shieldly analyze-iam ./iam-policy.json
  env:
    SHIELDLY_API_KEY: ${{ secrets.SHIELDLY_API_KEY }}
```

For pull-request gating with PR comments, use the
[Shieldly GitHub Action](https://github.com/shieldly-io/action) instead.

## Privacy

Shieldly does **not** log your policy input. Cache keys are one-way SHA-256
hashes of the input.

## Links

- Web app & demo: https://www.shieldly.io
- API reference: https://www.shieldly.io/docs/api
- Issues: https://github.com/shieldly-io/cli/issues

## Free tools & references (no signup)

No account required — these run in your browser or document the risks:

- [IAM Privilege Escalation Cheat Sheet](https://www.shieldly.io/iam/cheatsheet?utm_source=github&utm_medium=readme) — every common escalation path on one page, with fixes
- [Free browser tools](https://www.shieldly.io/tools?utm_source=github&utm_medium=readme) — IAM policy linter, trust policy explainer, S3 bucket policy checker, CloudFormation IAM checker, ARN parser, policy diff, CloudTrail least-privilege generator
- [Awesome AWS IAM Security](https://github.com/shieldly-io/awesome-aws-iam-security) — curated list of IAM security tools and references
- [IAM privilege escalation reference](https://www.shieldly.io/iam?utm_source=github&utm_medium=readme) — each method with a vulnerable policy, the exploit, and the fix

## License

MIT © Shieldly

---

*Amazon Web Services (AWS) is a trademark of Amazon.com, Inc. Shieldly is not
affiliated with, endorsed by, or sponsored by Amazon Web Services.*
