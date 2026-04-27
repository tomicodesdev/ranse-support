/**
 * Cloudflare Email provisioning — enables Email Routing on the zone and
 * creates a single address-to-Worker routing rule. All requests go through
 * direct `fetch` against api.cloudflare.com with a user-supplied scoped
 * token.
 *
 * Why no Email Sending: Cloudflare explicitly forbids Email Sending and
 * Email Routing on the same zone ("No other email services can be active
 * in the domain you are configuring." — developers.cloudflare.com/email-
 * routing/get-started/enable-email-routing/). For the OSS template's
 * single-domain default, Routing is the right choice — inbound to the
 * Worker is the load-bearing capability. Outbound replies go through
 * the Worker's `send_email` binding without needing Email Sending
 * onboarding. Users who specifically want DKIM-signed custom-domain
 * outbound can opt-in by setting Email Sending up on a separate
 * delegated zone — that's documented separately and not run by this
 * wizard.
 *
 * Helper functions for Email Sending (onboardSendingDomain,
 * getSendingDnsRecords) are kept exported below for any opt-in caller
 * that wants them, but the default applyProvisioning flow does not
 * touch them.
 */

const CF_API = 'https://api.cloudflare.com/client/v4';

interface CfEnvelope<T> {
  success: boolean;
  result: T;
  errors?: Array<{ code: number; message: string }>;
  messages?: Array<{ code: number; message: string }>;
}

async function cfFetch<T = any>(
  path: string,
  opts: { method: 'GET' | 'POST' | 'PUT' | 'DELETE'; token: string; body?: unknown },
): Promise<T> {
  const res = await fetch(`${CF_API}${path}`, {
    method: opts.method,
    headers: {
      authorization: `Bearer ${opts.token}`,
      'content-type': 'application/json',
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  let body: CfEnvelope<T>;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`CF ${opts.method} ${path}: non-JSON response (${res.status}): ${text.slice(0, 200)}`);
  }
  if (!res.ok || !body.success) {
    const errs = body.errors?.map((e) => `${e.code}: ${e.message}`).join('; ') ?? res.statusText;
    const err = new Error(`CF ${opts.method} ${path}: ${errs}`);
    (err as any).status = res.status;
    (err as any).cfErrors = body.errors ?? [];
    throw err;
  }
  return body.result;
}

export async function verifyToken(token: string) {
  return cfFetch<{ id: string; status: string; expires_on?: string }>('/user/tokens/verify', {
    method: 'GET',
    token,
  });
}

export async function findZone(token: string, domain: string) {
  // Walk from most specific to apex: email.ijamu.com → ijamu.com → com
  const parts = domain.split('.');
  for (let i = 0; i < parts.length - 1; i++) {
    const candidate = parts.slice(i).join('.');
    const zones = await cfFetch<Array<{ id: string; name: string }>>(
      `/zones?name=${encodeURIComponent(candidate)}`,
      { method: 'GET', token },
    );
    if (zones.length > 0) return { zoneId: zones[0].id, zoneName: zones[0].name };
  }
  return null;
}

export interface SendingSubdomain {
  tag: string;
  name: string;
  enabled?: boolean;
  dkim_selector?: string;
}

/**
 * Idempotently ensure a sending subdomain exists. The Cloudflare API exposes
 * `GET /subdomains/:tag` (not by name), so we list-and-match-by-name to find
 * an existing one before creating.
 */
export async function onboardSendingDomain(
  token: string,
  zoneId: string,
  name: string,
): Promise<{ created: boolean; subdomain: SendingSubdomain }> {
  const list = await cfFetch<SendingSubdomain[]>(
    `/zones/${zoneId}/email/sending/subdomains`,
    { method: 'GET', token },
  ).catch(() => [] as SendingSubdomain[]);
  const found = list.find((s) => s.name === name);
  if (found) return { created: false, subdomain: found };

  const created = await cfFetch<SendingSubdomain>(
    `/zones/${zoneId}/email/sending/subdomains`,
    { method: 'POST', token, body: { name } },
  );
  return { created: true, subdomain: created };
}

export interface SendingDnsRecord {
  type: string;
  name: string;
  content: string;
  priority?: number;
  reason?: string;
}

export async function getSendingDnsRecords(
  token: string,
  zoneId: string,
  tag: string,
): Promise<SendingDnsRecord[]> {
  const res = await cfFetch<any>(
    `/zones/${zoneId}/email/sending/subdomains/${tag}/dns`,
    { method: 'GET', token },
  );
  // Endpoint shape varies in beta — accept both {records: [...]} and [...] directly.
  const list = Array.isArray(res) ? res : (res.records ?? res.dns_records ?? []);
  return list as SendingDnsRecord[];
}

export async function addDnsRecord(token: string, zoneId: string, record: SendingDnsRecord) {
  return cfFetch<any>(`/zones/${zoneId}/dns_records`, {
    method: 'POST',
    token,
    body: { ...record, ttl: 1, proxied: false },
  });
}

export async function enableEmailRouting(token: string, zoneId: string) {
  // Probe current state. If the GET fails, surface the error rather than
  // silently falling through — earlier "tolerance" here masked real auth
  // failures and reported the zone as enabled when it wasn't.
  let probed: { enabled?: boolean; status?: string } | null = null;
  try {
    probed = await cfFetch<{ enabled?: boolean; status?: string }>(
      `/zones/${zoneId}/email/routing`,
      { method: 'GET', token },
    );
  } catch (err: any) {
    // GET requires Email Routing Addresses: Read (account scope) on most
    // accounts. If it 10000s, fall through to POST and let that be the
    // authority; a 10000 there means we genuinely don't have permission.
    if (err?.cfErrors?.[0]?.code !== 10000) throw err;
  }
  const enabled =
    probed?.enabled === true ||
    probed?.status === 'ready' ||
    probed?.status === 'enabled';
  if (enabled) return { alreadyEnabled: true };

  try {
    await cfFetch<any>(`/zones/${zoneId}/email/routing/enable`, { method: 'POST', token });
    return { alreadyEnabled: false };
  } catch (err: any) {
    const code = err?.cfErrors?.[0]?.code;
    if (code === 10000) {
      throw new Error(
        'Token cannot enable Email Routing. The /email/routing/enable endpoint ' +
          'requires "Account · Email Routing Addresses: Edit" — not just ' +
          '"Zone · Email Routing Rules: Edit". Recreate the token with that ' +
          'permission added, or click "Onboard Domain" in the Cloudflare ' +
          'dashboard (Email → Email Routing) to enable manually.',
      );
    }
    throw err;
  }
}

export async function createRoutingRule(
  token: string,
  zoneId: string,
  mailboxAddress: string,
  workerName: string,
) {
  // Idempotent: skip if a rule matching this exact destination already exists.
  const existing = await cfFetch<Array<any>>(`/zones/${zoneId}/email/routing/rules`, {
    method: 'GET',
    token,
  }).catch(() => [] as any[]);
  const dup = (existing ?? []).find((r: any) =>
    r.matchers?.some((m: any) => m.type === 'literal' && m.field === 'to' && m.value === mailboxAddress),
  );
  if (dup) return { created: false, id: dup.id };
  const rule = await cfFetch<any>(`/zones/${zoneId}/email/routing/rules`, {
    method: 'POST',
    token,
    body: {
      name: `Ranse: ${mailboxAddress}`,
      enabled: true,
      matchers: [{ type: 'literal', field: 'to', value: mailboxAddress }],
      actions: [{ type: 'worker', value: [workerName] }],
    },
  });
  return { created: true, id: rule.id };
}

export interface ProvisionStep {
  id: string;
  label: string;
  status: 'ok' | 'fail' | 'skipped';
  message?: string;
  dns_records?: SendingDnsRecord[];
}

export interface ProvisionInput {
  apiToken: string;
  accountId: string;
  domain: string;
  mailboxAddress: string;
  workerName: string;
}

export async function applyProvisioning(input: ProvisionInput): Promise<ProvisionStep[]> {
  const steps: ProvisionStep[] = [];

  try {
    const t = await verifyToken(input.apiToken);
    if (t.status !== 'active') throw new Error(`Token status is "${t.status}"`);
    steps.push({ id: 'token', label: 'API token valid', status: 'ok' });
  } catch (err: any) {
    steps.push({ id: 'token', label: 'API token', status: 'fail', message: err.message });
    return steps;
  }

  // Zone is required for Email Routing. Fail-fast if the domain isn't on
  // this Cloudflare account.
  const zone = await findZone(input.apiToken, input.domain).catch(() => null);
  if (!zone) {
    steps.push({
      id: 'zone',
      label: `Zone for "${input.domain}" not found on this Cloudflare account`,
      status: 'fail',
      message:
        'Email Routing requires the domain to be a zone on this account. Add the domain at dash.cloudflare.com → Add a site, then retry.',
    });
    return steps;
  }
  steps.push({ id: 'zone', label: `Zone "${zone.zoneName}" found on Cloudflare`, status: 'ok' });

  // Cloudflare forbids Email Routing on a zone that has Email Sending active.
  // If a sending subdomain exists, we can't enable Routing — surface a
  // pointer to the un-onboard step rather than letting /enable 10000 with
  // an opaque "Authentication error" later on.
  try {
    const sending = await cfFetch<SendingSubdomain[]>(
      `/zones/${zone.zoneId}/email/sending/subdomains`,
      { method: 'GET', token: input.apiToken },
    ).catch(() => [] as SendingSubdomain[]);
    if (sending.length > 0) {
      const names = sending.map((s) => s.name).join(', ');
      steps.push({
        id: 'conflict',
        label: 'Email Sending is active on this zone — must be removed first',
        status: 'fail',
        message:
          `Cloudflare does not allow Email Sending and Email Routing on the same zone. Found Email Sending subdomain(s): ${names}.\n\n` +
          `To unblock setup, delete the sending subdomain in the Cloudflare dashboard (Email → Email Sending → click the domain → Delete), or via API:\n\n` +
          `    curl -X DELETE -H "Authorization: Bearer <token>" \\\n      https://api.cloudflare.com/client/v4/zones/${zone.zoneId}/email/sending/subdomains/<subdomain_id>\n\n` +
          `Once cleared, Retry this step. (Ranse uses the Worker's send_email binding for outbound replies — Email Sending onboarding is not required.)`,
      });
      return steps;
    }
  } catch {
    // Token may lack Email Sending: Read; ignore — if Sending IS active and
    // we can't see it, /enable will surface the conflict anyway.
  }

  try {
    const er = await enableEmailRouting(input.apiToken, zone.zoneId);
    steps.push({
      id: 'routing',
      label: er.alreadyEnabled ? 'Email Routing already enabled' : 'Email Routing enabled',
      status: 'ok',
    });
  } catch (err: any) {
    steps.push({ id: 'routing', label: 'Enable Email Routing', status: 'fail', message: err.message });
    return steps;
  }

  try {
    const rule = await createRoutingRule(
      input.apiToken,
      zone.zoneId,
      input.mailboxAddress,
      input.workerName,
    );
    steps.push({
      id: 'rule',
      label: rule.created
        ? `Routing rule created: ${input.mailboxAddress} → ${input.workerName}`
        : `Routing rule already present: ${input.mailboxAddress}`,
      status: 'ok',
    });
  } catch (err: any) {
    steps.push({ id: 'rule', label: 'Create routing rule', status: 'fail', message: err.message });
  }

  return steps;
}
