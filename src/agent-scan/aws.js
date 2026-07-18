/**
 * AWS credential/role resolution for agent-scan — used only for --role-arn
 * and --profile. Uses the caller's local AWS credentials; nothing is uploaded.
 *
 * AWS SDK clients are imported lazily so the --policy-file path never touches
 * SDK code at runtime.
 */

/**
 * @typedef {object} ResolvedIdentity
 * @property {string} label - Human-readable identity label (role/user name).
 * @property {Array<{name: string, document: object}>} policies - Attached + inline policy documents.
 * @property {boolean|null} hasPermissionBoundary - null when not determinable.
 */

function decodePolicyDocument(doc) {
  if (typeof doc !== 'string') return doc;
  return JSON.parse(decodeURIComponent(doc));
}

async function iamClient(profileOrCredentials, region) {
  const { IAMClient } = await import('@aws-sdk/client-iam');
  if (!profileOrCredentials) return new IAMClient({});
  if (typeof profileOrCredentials === 'string') {
    const { fromIni } = await import('@aws-sdk/credential-providers');
    return new IAMClient({ credentials: fromIni({ profile: profileOrCredentials }) });
  }
  // Explicit credentials (e.g. from an STS AssumeRole call) — used by the
  // backend drift-monitor, which has no local AWS profile to reference.
  return new IAMClient({ region, credentials: profileOrCredentials });
}

/**
 * Fetch attached + inline policies (and boundary presence) for an IAM role.
 * @param {string} roleArn
 * @param {string|{accessKeyId: string, secretAccessKey: string, sessionToken: string}} [profileOrCredentials]
 *   A local AWS profile name, or explicit assumed-role credentials.
 * @param {string} [region]
 * @returns {Promise<ResolvedIdentity>}
 */
export async function fetchRolePolicies(roleArn, profileOrCredentials, region) {
  const roleName = roleArn.split('/').pop();
  const iam = await iamClient(profileOrCredentials, region);
  const {
    GetPolicyCommand,
    GetPolicyVersionCommand,
    GetRoleCommand,
    GetRolePolicyCommand,
    ListAttachedRolePoliciesCommand,
    ListRolePoliciesCommand,
  } = await import('@aws-sdk/client-iam');

  const role = await iam.send(new GetRoleCommand({ RoleName: roleName }));
  const hasPermissionBoundary = Boolean(role.Role?.PermissionsBoundary);

  const policies = [];

  const attached = await iam.send(new ListAttachedRolePoliciesCommand({ RoleName: roleName }));
  for (const p of attached.AttachedPolicies || []) {
    const pol = await iam.send(new GetPolicyCommand({ PolicyArn: p.PolicyArn }));
    const ver = await iam.send(
      new GetPolicyVersionCommand({
        PolicyArn: p.PolicyArn,
        VersionId: pol.Policy.DefaultVersionId,
      })
    );
    policies.push({
      name: `attached:${p.PolicyName}`,
      document: decodePolicyDocument(ver.PolicyVersion.Document),
    });
  }

  const inline = await iam.send(new ListRolePoliciesCommand({ RoleName: roleName }));
  for (const name of inline.PolicyNames || []) {
    const pol = await iam.send(new GetRolePolicyCommand({ RoleName: roleName, PolicyName: name }));
    policies.push({ name: `inline:${name}`, document: decodePolicyDocument(pol.PolicyDocument) });
  }

  return { label: `role/${roleName}`, policies, hasPermissionBoundary };
}

/**
 * Fetch attached + inline policies (and boundary presence) for an IAM user.
 * @param {string} userName
 * @param {string} [profile]
 * @returns {Promise<ResolvedIdentity>}
 */
export async function fetchUserPolicies(userName, profile) {
  const iam = await iamClient(profile);
  const {
    GetGroupPolicyCommand,
    GetPolicyCommand,
    GetPolicyVersionCommand,
    GetUserCommand,
    GetUserPolicyCommand,
    ListAttachedGroupPoliciesCommand,
    ListAttachedUserPoliciesCommand,
    ListGroupPoliciesCommand,
    ListGroupsForUserCommand,
    ListUserPoliciesCommand,
  } = await import('@aws-sdk/client-iam');

  const user = await iam.send(new GetUserCommand({ UserName: userName }));
  const hasPermissionBoundary = Boolean(user.User?.PermissionsBoundary);

  const policies = [];

  const attached = await iam.send(new ListAttachedUserPoliciesCommand({ UserName: userName }));
  for (const p of attached.AttachedPolicies || []) {
    const pol = await iam.send(new GetPolicyCommand({ PolicyArn: p.PolicyArn }));
    const ver = await iam.send(
      new GetPolicyVersionCommand({
        PolicyArn: p.PolicyArn,
        VersionId: pol.Policy.DefaultVersionId,
      })
    );
    policies.push({
      name: `attached:${p.PolicyName}`,
      document: decodePolicyDocument(ver.PolicyVersion.Document),
    });
  }

  const inline = await iam.send(new ListUserPoliciesCommand({ UserName: userName }));
  for (const name of inline.PolicyNames || []) {
    const pol = await iam.send(new GetUserPolicyCommand({ UserName: userName, PolicyName: name }));
    policies.push({ name: `inline:${name}`, document: decodePolicyDocument(pol.PolicyDocument) });
  }

  // Group memberships grant permissions too — a user with no direct policies
  // can still be admin via a group.
  const groups = await iam.send(new ListGroupsForUserCommand({ UserName: userName }));
  for (const g of groups.Groups || []) {
    const gAttached = await iam.send(
      new ListAttachedGroupPoliciesCommand({ GroupName: g.GroupName })
    );
    for (const p of gAttached.AttachedPolicies || []) {
      const pol = await iam.send(new GetPolicyCommand({ PolicyArn: p.PolicyArn }));
      const ver = await iam.send(
        new GetPolicyVersionCommand({
          PolicyArn: p.PolicyArn,
          VersionId: pol.Policy.DefaultVersionId,
        })
      );
      policies.push({
        name: `group:${g.GroupName}/${p.PolicyName}`,
        document: decodePolicyDocument(ver.PolicyVersion.Document),
      });
    }
    const gInline = await iam.send(new ListGroupPoliciesCommand({ GroupName: g.GroupName }));
    for (const name of gInline.PolicyNames || []) {
      const pol = await iam.send(
        new GetGroupPolicyCommand({ GroupName: g.GroupName, PolicyName: name })
      );
      policies.push({
        name: `group:${g.GroupName}/inline:${name}`,
        document: decodePolicyDocument(pol.PolicyDocument),
      });
    }
  }

  return { label: `user/${userName}`, policies, hasPermissionBoundary };
}

/**
 * Resolve what identity an AWS profile maps to, then fetch its policies.
 * Supports IAM users and assumed roles.
 * @param {string} profile
 * @returns {Promise<ResolvedIdentity>}
 */
export async function resolveProfile(profile) {
  const { GetCallerIdentityCommand, STSClient } = await import('@aws-sdk/client-sts');
  const { fromIni } = await import('@aws-sdk/credential-providers');
  const sts = new STSClient({ credentials: fromIni({ profile }) });
  const id = await sts.send(new GetCallerIdentityCommand({}));
  const arn = id.Arn || '';

  // arn:aws:iam::123456789012:user/name
  const userMatch = arn.match(/:user\/(.+)$/);
  if (userMatch) return fetchUserPolicies(userMatch[1], profile);

  // arn:aws:sts::123456789012:assumed-role/RoleName/session
  const assumedMatch = arn.match(/:assumed-role\/([^/]+)\//);
  if (assumedMatch) {
    const account = arn.match(/::(\d{12}):/)?.[1];
    return fetchRolePolicies(`arn:aws:iam::${account}:role/${assumedMatch[1]}`, profile);
  }

  throw new Error(
    `Profile "${profile}" resolves to an unsupported identity type: ${arn}. Use --role-arn instead.`
  );
}
