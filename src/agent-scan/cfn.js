/**
 * Offline CloudFormation blast-radius scanning.
 *
 * Finds agent-like resources in a synthesized template — Bedrock agents, ECS
 * task definitions, Lambda functions — and, when their IAM role is defined in
 * the same template, runs the role's inline policies through the same
 * blast-radius engine used elsewhere in agent-scan. Pure, offline, no network:
 * a role referenced by literal ARN or defined in a different stack can't be
 * resolved this way (use --role-arn against the deployed role instead).
 * Managed-policy ARNs are reported but not expanded — their document isn't in
 * the template.
 */

import { analyzePolicy, dedupeFindings } from './engine.js';

/** CloudFormation resource types treated as "deploys an AI agent". */
const AGENT_RESOURCE_TYPES = {
  'AWS::Bedrock::Agent': { kind: 'Bedrock Agent', roleProps: ['AgentResourceRoleArn'] },
  'AWS::ECS::TaskDefinition': {
    kind: 'ECS Task Definition',
    roleProps: ['TaskRoleArn', 'ExecutionRoleArn'],
  },
  'AWS::Lambda::Function': { kind: 'Lambda Function', roleProps: ['Role'] },
};

/** Resolve a CFN intrinsic (Ref / Fn::GetAtt) to the logical ID it points at. */
function resolveLogicalId(value) {
  if (!value || typeof value !== 'object') return null;
  if (typeof value.Ref === 'string') return value.Ref;
  if (Array.isArray(value['Fn::GetAtt'])) return value['Fn::GetAtt'][0];
  if (typeof value['Fn::GetAtt'] === 'string') return value['Fn::GetAtt'].split('.')[0];
  return null;
}

/** Findings + managed-policy ARNs for one in-template AWS::IAM::Role resource. */
function analyzeRoleResource(resources, roleLogicalId, sourceLabel) {
  const findings = [];
  const managedPolicyArns = [];
  const role = resources[roleLogicalId];
  if (role?.Type !== 'AWS::IAM::Role') {
    return { findings, managedPolicyArns, resolved: false };
  }
  const props = role.Properties || {};
  for (const policy of props.Policies || []) {
    if (policy?.PolicyDocument) {
      const name = policy.PolicyName || 'unnamed';
      findings.push(...analyzePolicy(policy.PolicyDocument, `${sourceLabel} · inline:${name}`));
    }
  }
  for (const arn of props.ManagedPolicyArns || []) {
    if (typeof arn === 'string') managedPolicyArns.push(arn);
  }
  return { findings, managedPolicyArns, resolved: true };
}

/**
 * @typedef {object} CfnAgentResource
 * @property {string} logicalId
 * @property {string} resourceType
 * @property {string} kind
 * @property {string[]} roleLogicalIds - In-template IAM::Role logical IDs resolved.
 * @property {import('./engine.js').Finding[]} findings
 * @property {string[]} managedPolicyArns - Attached but not expanded offline.
 */

/**
 * Scan a parsed CloudFormation template for agent-like resources with an
 * in-template IAM role.
 * @param {object} template - Parsed CloudFormation JSON template.
 * @returns {CfnAgentResource[]}
 */
export function scanCloudFormationTemplate(template) {
  const resources = template?.Resources || {};
  const agents = [];

  for (const [logicalId, resource] of Object.entries(resources)) {
    const spec = AGENT_RESOURCE_TYPES[resource?.Type];
    if (!spec) continue;
    const props = resource.Properties || {};

    const findings = [];
    const managedPolicyArns = new Set();
    const roleLogicalIds = [];

    for (const roleProp of spec.roleProps) {
      const roleLogicalId = resolveLogicalId(props[roleProp]);
      if (!roleLogicalId) continue;
      const label = `${logicalId} (${spec.kind})`;
      const result = analyzeRoleResource(resources, roleLogicalId, label);
      if (!result.resolved) continue;
      roleLogicalIds.push(roleLogicalId);
      findings.push(...result.findings);
      for (const arn of result.managedPolicyArns) managedPolicyArns.add(arn);
    }

    // Role is a literal ARN, defined in a different stack, or absent — nothing
    // to analyze offline for this resource.
    if (roleLogicalIds.length === 0) continue;

    agents.push({
      logicalId,
      resourceType: resource.Type,
      kind: spec.kind,
      roleLogicalIds,
      findings: dedupeFindings(findings),
      managedPolicyArns: [...managedPolicyArns],
    });
  }

  return agents;
}
