/**
 * Blast-radius severity rules — data-driven table.
 *
 * Each rule maps IAM action patterns to a category + severity. Rules are
 * matched by glob intersection, so a policy granting `s3:*` matches a rule
 * pattern `s3:Delete*` without expanding the full AWS action list.
 *
 * Adding a rule = adding an entry here. No code changes needed.
 *
 * Categories (see PLAN-agent-blast-radius.md):
 *   DESTRUCTIVE   — can delete/terminate/modify infrastructure or data
 *   ESCALATION    — can grant itself (or others) more permissions
 *   DATA_ACCESS   — can read sensitive data stores
 *   COST_RISK     — can run up the AWS bill
 *   WILDCARD      — structurally unbounded grants
 *   NO_GUARDRAILS — missing boundaries / hardcoded credentials
 */

/** @typedef {'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'} Severity */

/**
 * @typedef {object} Rule
 * @property {string} id - Stable rule ID (used by SARIF and --ignore).
 * @property {string} category
 * @property {Severity} severity - Base severity when matched.
 * @property {Severity} [severityOnWildcardResource] - Bump when Resource is "*".
 * @property {string[]} actions - Action glob patterns that trigger the rule.
 * @property {boolean} [requiresNoCondition] - Only fire when the statement has no Condition.
 * @property {string} title
 * @property {string} description
 * @property {string} remediation
 */

/** @type {Rule[]} */
export const ACTION_RULES = [
  // ── DESTRUCTIVE ──────────────────────────────────────────────────────────
  {
    id: 'BR-DEST-S3',
    category: 'DESTRUCTIVE',
    severity: 'HIGH',
    severityOnWildcardResource: 'CRITICAL',
    actions: [
      's3:DeleteObject',
      's3:DeleteObjectVersion',
      's3:DeleteBucket',
      's3:PutBucketPolicy',
      's3:PutLifecycleConfiguration',
    ],
    title: 'Can delete or rewrite S3 data',
    description: 'The agent can permanently delete S3 objects/buckets or rewrite bucket policy.',
    remediation: 'Scope to specific bucket ARNs; add an explicit Deny for s3:DeleteBucket.',
  },
  {
    id: 'BR-DEST-RDS',
    category: 'DESTRUCTIVE',
    severity: 'HIGH',
    severityOnWildcardResource: 'CRITICAL',
    actions: [
      'rds:DeleteDBInstance',
      'rds:DeleteDBCluster',
      'rds:DeleteDBSnapshot',
      'rds:ModifyDBInstance',
    ],
    title: 'Can delete or modify RDS databases',
    description: 'The agent can drop database instances, clusters, or their snapshots.',
    remediation: 'Remove rds:Delete*/rds:Modify* or scope to non-production DB ARNs.',
  },
  {
    id: 'BR-DEST-DDB',
    category: 'DESTRUCTIVE',
    severity: 'HIGH',
    severityOnWildcardResource: 'CRITICAL',
    actions: [
      'dynamodb:DeleteTable',
      'dynamodb:DeleteItem',
      'dynamodb:BatchWriteItem',
      'dynamodb:UpdateTable',
    ],
    title: 'Can delete DynamoDB tables or items',
    description: 'The agent can drop whole tables or bulk-delete items.',
    remediation: 'Scope to specific table ARNs; deny dynamodb:DeleteTable.',
  },
  {
    id: 'BR-DEST-EC2',
    category: 'DESTRUCTIVE',
    severity: 'HIGH',
    severityOnWildcardResource: 'CRITICAL',
    actions: [
      'ec2:TerminateInstances',
      'ec2:StopInstances',
      'ec2:DeleteVolume',
      'ec2:DeleteSnapshot',
      'ec2:ModifyInstanceAttribute',
    ],
    title: 'Can terminate or modify EC2 instances',
    description: 'The agent can terminate instances or delete volumes/snapshots.',
    remediation:
      'Restrict with resource tags (aws:ResourceTag) or remove terminate/delete actions.',
  },
  {
    id: 'BR-DEST-ECS',
    category: 'DESTRUCTIVE',
    severity: 'HIGH',
    severityOnWildcardResource: 'CRITICAL',
    actions: ['ecs:DeleteService', 'ecs:DeleteCluster', 'ecs:StopTask', 'ecs:UpdateService'],
    title: 'Can delete or modify ECS services',
    description: 'The agent can stop tasks, delete services, or change service definitions.',
    remediation: 'Scope to specific cluster/service ARNs.',
  },
  {
    id: 'BR-DEST-LAMBDA',
    category: 'DESTRUCTIVE',
    severity: 'HIGH',
    severityOnWildcardResource: 'CRITICAL',
    actions: [
      'lambda:DeleteFunction',
      'lambda:UpdateFunctionCode',
      'lambda:UpdateFunctionConfiguration',
      'lambda:PutFunctionConcurrency',
    ],
    title: 'Can delete or rewrite Lambda functions',
    description: 'The agent can delete functions or replace their code — a code-injection path.',
    remediation:
      'Remove lambda:UpdateFunctionCode/DeleteFunction or scope to specific function ARNs.',
  },
  {
    id: 'BR-DEST-CFN',
    category: 'DESTRUCTIVE',
    severity: 'HIGH',
    severityOnWildcardResource: 'CRITICAL',
    actions: [
      'cloudformation:DeleteStack',
      'cloudformation:UpdateStack',
      'cloudformation:ExecuteChangeSet',
    ],
    title: 'Can delete or mutate CloudFormation stacks',
    description: 'Deleting a stack tears down every resource it manages.',
    remediation: 'Scope to specific stack ARNs; enable stack termination protection.',
  },
  {
    id: 'BR-DEST-R53',
    category: 'DESTRUCTIVE',
    severity: 'HIGH',
    severityOnWildcardResource: 'CRITICAL',
    actions: ['route53:ChangeResourceRecordSets', 'route53:DeleteHostedZone'],
    title: 'Can change DNS records',
    description: 'The agent can repoint or delete DNS — a traffic-hijack path.',
    remediation: 'Scope to specific hosted-zone ARNs; restrict record types via conditions.',
  },

  // ── ESCALATION ───────────────────────────────────────────────────────────
  {
    id: 'BR-ESC-PASSROLE',
    category: 'ESCALATION',
    severity: 'HIGH',
    severityOnWildcardResource: 'CRITICAL',
    actions: ['iam:PassRole'],
    title: 'Can pass IAM roles to services',
    description:
      'iam:PassRole lets the agent hand a (possibly more privileged) role to a service it controls.',
    remediation:
      'Scope Resource to the exact role ARNs the agent must pass; add iam:PassedToService condition.',
  },
  {
    id: 'BR-ESC-CREATEKEY',
    category: 'ESCALATION',
    severity: 'CRITICAL',
    actions: ['iam:CreateAccessKey', 'iam:CreateLoginProfile', 'iam:UpdateLoginProfile'],
    title: 'Can mint credentials for other identities',
    description:
      'The agent can create access keys or console passwords for other users — full account takeover path.',
    remediation: 'Remove these actions; agents should never manage other identities’ credentials.',
  },
  {
    id: 'BR-ESC-ATTACH',
    category: 'ESCALATION',
    severity: 'CRITICAL',
    actions: [
      'iam:AttachUserPolicy',
      'iam:AttachRolePolicy',
      'iam:AttachGroupPolicy',
      'iam:PutUserPolicy',
      'iam:PutRolePolicy',
      'iam:PutGroupPolicy',
      'iam:CreatePolicyVersion',
      'iam:SetDefaultPolicyVersion',
      'iam:AddUserToGroup',
      'iam:UpdateAssumeRolePolicy',
    ],
    title: 'Can grant itself more permissions',
    description:
      'Policy-attachment/versioning actions are a direct privilege-escalation path to admin.',
    remediation: 'Remove all iam:Attach*/Put*/CreatePolicyVersion actions from agent credentials.',
  },
  {
    id: 'BR-ESC-ASSUME-STAR',
    category: 'ESCALATION',
    severity: 'CRITICAL',
    actions: ['sts:AssumeRole'],
    requiresWildcardResource: true,
    title: 'Can assume any role in the account',
    description:
      'sts:AssumeRole on Resource "*" means the agent inherits any role that trusts this principal.',
    remediation: 'List the exact role ARNs the agent may assume.',
  },

  // ── DATA_ACCESS ──────────────────────────────────────────────────────────
  {
    id: 'BR-DATA-S3',
    category: 'DATA_ACCESS',
    severity: 'MEDIUM',
    severityOnWildcardResource: 'HIGH',
    actions: ['s3:GetObject', 's3:ListBucket'],
    title: 'Can read S3 data',
    description: 'The agent can read objects from S3 buckets in scope.',
    remediation: 'Scope to the specific buckets/prefixes the agent needs.',
  },
  {
    id: 'BR-DATA-SECRETS',
    category: 'DATA_ACCESS',
    severity: 'HIGH',
    severityOnWildcardResource: 'CRITICAL',
    actions: ['secretsmanager:GetSecretValue', 'secretsmanager:ListSecrets'],
    title: 'Can read Secrets Manager secrets',
    description: 'The agent can exfiltrate stored credentials, API keys, and connection strings.',
    remediation: 'Scope to specific secret ARNs; never grant on "*".',
  },
  {
    id: 'BR-DATA-SSM',
    category: 'DATA_ACCESS',
    severity: 'HIGH',
    severityOnWildcardResource: 'CRITICAL',
    actions: ['ssm:GetParameter', 'ssm:GetParameters', 'ssm:GetParametersByPath'],
    title: 'Can read SSM parameters',
    description: 'SSM Parameter Store commonly holds secrets; the agent can read them.',
    remediation: 'Scope to specific parameter paths (arn:...:parameter/app/agent/*).',
  },
  {
    id: 'BR-DATA-RDS-SNAP',
    category: 'DATA_ACCESS',
    severity: 'MEDIUM',
    severityOnWildcardResource: 'HIGH',
    actions: ['rds:CopyDBSnapshot', 'rds:ModifyDBSnapshotAttribute', 'rds:DescribeDBSnapshots'],
    title: 'Can access RDS snapshots',
    description: 'Snapshot copy/share actions are a database-exfiltration path.',
    remediation: 'Remove snapshot-sharing actions; deny rds:ModifyDBSnapshotAttribute.',
  },
  {
    id: 'BR-DATA-DDB',
    category: 'DATA_ACCESS',
    severity: 'MEDIUM',
    severityOnWildcardResource: 'HIGH',
    actions: [
      'dynamodb:GetItem',
      'dynamodb:BatchGetItem',
      'dynamodb:Scan',
      'dynamodb:Query',
      'dynamodb:ExportTableToPointInTime',
    ],
    title: 'Can read DynamoDB data',
    description: 'The agent can scan/export tables in scope.',
    remediation: 'Scope to specific table ARNs; avoid granting Scan on "*".',
  },

  // ── COST_RISK ────────────────────────────────────────────────────────────
  {
    id: 'BR-COST-EC2',
    category: 'COST_RISK',
    severity: 'MEDIUM',
    severityOnWildcardResource: 'HIGH',
    requiresNoCondition: true,
    actions: ['ec2:RunInstances'],
    title: 'Can launch EC2 instances without constraints',
    description:
      'Unconditioned ec2:RunInstances lets the agent launch any instance type — cryptomining risk.',
    remediation: 'Add ec2:InstanceType condition limiting to small instance types.',
  },
  {
    id: 'BR-COST-SAGEMAKER',
    category: 'COST_RISK',
    severity: 'MEDIUM',
    severityOnWildcardResource: 'HIGH',
    requiresNoCondition: true,
    actions: [
      'sagemaker:CreateTrainingJob',
      'sagemaker:CreateEndpoint',
      'sagemaker:CreateNotebookInstance',
    ],
    title: 'Can create SageMaker resources without constraints',
    description: 'SageMaker training jobs and endpoints on GPU instances run up bills fast.',
    remediation: 'Add sagemaker:InstanceTypes conditions or remove creation actions.',
  },
  {
    id: 'BR-COST-BEDROCK',
    category: 'COST_RISK',
    severity: 'MEDIUM',
    severityOnWildcardResource: 'HIGH',
    requiresNoCondition: true,
    actions: ['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream'],
    title: 'Can invoke Bedrock models without constraints',
    description:
      'Unbounded model invocation is a runaway-cost path (and a data-egress path via prompts).',
    remediation: 'Scope Resource to the specific model ARNs the agent needs.',
  },
];

/**
 * Statement-level structural rules (WILDCARD category) — matched on statement
 * shape, not individual actions.
 */
export const STRUCTURAL_RULES = {
  ACTION_STAR: {
    id: 'BR-WILD-ACTION',
    category: 'WILDCARD',
    severity: 'CRITICAL',
    title: 'Action "*" — unrestricted actions',
    description:
      'The statement allows every AWS action. Combined with a broad Resource this is administrator access.',
    remediation: 'Enumerate the specific actions the agent needs.',
  },
  RESOURCE_STAR: {
    id: 'BR-WILD-RESOURCE',
    category: 'WILDCARD',
    severity: 'MEDIUM',
    title: 'Resource "*" — applies to every resource',
    description: 'The statement applies to all resources in the account.',
    remediation: 'Replace with specific ARNs.',
  },
  SERVICE_STAR: {
    id: 'BR-WILD-SERVICE',
    category: 'WILDCARD',
    severity: 'HIGH',
    title: 'Service-wide wildcard action',
    description: 'Grants every action in a service.',
    remediation: 'Enumerate the specific actions the agent needs.',
  },
  NOTACTION_ALLOW: {
    id: 'BR-WILD-NOTACTION',
    category: 'WILDCARD',
    severity: 'HIGH',
    title: 'Allow + NotAction',
    description:
      'NotAction with Allow grants every action NOT listed — usually far broader than intended.',
    remediation: 'Rewrite as an explicit Action allow-list.',
  },
  TRUST_OPEN_PRINCIPAL: {
    id: 'BR-TRUST-OPEN-PRINCIPAL',
    category: 'ESCALATION',
    severity: 'CRITICAL',
    title: 'Trust policy allows any principal to assume this role',
    description:
      'Principal "*" (or AWS "*") with no Condition lets any AWS identity anywhere assume the role and inherit all of its permissions.',
    remediation:
      'Restrict Principal to the exact service or account/role ARNs that need the role, or add a scoping Condition (aws:SourceAccount, aws:SourceArn, sts:ExternalId).',
  },
  TRUST_SERVICE_NO_SCOPE: {
    id: 'BR-TRUST-SERVICE-NO-SCOPE',
    category: 'ESCALATION',
    severity: 'MEDIUM',
    title: 'Service trust without aws:SourceAccount/aws:SourceArn condition',
    description:
      'A service principal may assume this role without a source scoping condition — the classic confused-deputy setup if the service acts on behalf of other accounts.',
    remediation:
      'Add a Condition with aws:SourceAccount (and aws:SourceArn where supported) to the trust statement.',
  },
};

/** NO_GUARDRAILS rules — matched on scan context, not policy statements. */
export const GUARDRAIL_RULES = {
  HARDCODED_KEY: {
    id: 'BR-GUARD-HARDCODED-KEY',
    category: 'NO_GUARDRAILS',
    severity: 'CRITICAL',
    title: 'Hardcoded AWS access key in agent config',
    description:
      'A long-lived access key ID (AKIA…) is embedded in the agent config file. Anyone with the file has the credentials.',
    remediation:
      'Rotate the key immediately; switch to an AWS profile or short-lived role credentials.',
  },
  NO_BOUNDARY: {
    id: 'BR-GUARD-NO-BOUNDARY',
    category: 'NO_GUARDRAILS',
    severity: 'LOW',
    title: 'No permission boundary on the agent identity',
    description:
      'Without a permission boundary, any future policy attachment widens the agent’s blast radius unchecked.',
    remediation: 'Attach a permission boundary that caps the agent to its expected services.',
  },
};

export const CATEGORY_ORDER = [
  'ESCALATION',
  'DESTRUCTIVE',
  'WILDCARD',
  'DATA_ACCESS',
  'COST_RISK',
  'NO_GUARDRAILS',
];
