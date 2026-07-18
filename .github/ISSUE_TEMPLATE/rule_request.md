---
name: Agent Blast-Radius rule request
about: Propose a new blast-radius rule, or a change to an existing one
title: "[rule] "
labels: rule-request
---

**Category** (DESTRUCTIVE / ESCALATION / DATA_ACCESS / COST_RISK / WILDCARD / NO_GUARDRAILS):

**Proposed rule:**
- Actions it should match (IAM action patterns, e.g. `s3:PutBucketAcl`):
- Suggested severity (LOW / MEDIUM / HIGH / CRITICAL), and whether it should bump on
  `Resource: "*"`:

**Why this matters** (what could an agent do with this permission?):

**Example policy statement that should trigger it:**
```json

```
