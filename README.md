# @shieldly/cli

**AI-Powered Security Analysis for AWS — official CLI.**

Analyze AWS IAM policies and CloudFormation templates for security risks from
any terminal, shell script, or CI/CD pipeline. Powered by
[Shieldly](https://www.shieldly.io).

```bash
npm install -g @shieldly/cli
```

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
| `shieldly analyze-iam <policy-file>` | Analyze an IAM policy for security issues |
| `shieldly analyze-cf <template-file>` | Analyze a CloudFormation template |
| `shieldly api-keys list\|create\|revoke` | Manage API keys |
| `shieldly completion bash\|zsh\|install` | Shell completion |

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
- [Free browser tools](https://www.shieldly.io/tools?utm_source=github&utm_medium=readme) — IAM policy linter, trust policy explainer, S3 bucket policy checker, CloudFormation IAM checker
- [IAM privilege escalation reference](https://www.shieldly.io/iam?utm_source=github&utm_medium=readme) — each method with a vulnerable policy, the exploit, and the fix

## License

MIT © Shieldly

---

*Amazon Web Services (AWS) is a trademark of Amazon.com, Inc. Shieldly is not
affiliated with, endorsed by, or sponsored by Amazon Web Services.*
