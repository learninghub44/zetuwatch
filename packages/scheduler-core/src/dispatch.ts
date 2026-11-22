import {
  claimDueMonitors,
  deferMonitorClaim,
  finalizeMonitorCheck,
  type ClaimedMonitor
} from "./claims";
import {
  sendProbeJob,
  validateProbeAgentEndpoint,
  type ProbeJob,
  type ProbeResult
} from "../../probe-client/src/client.mjs";

export interface ProbeDispatchEnv {
  DB: D1Database;
  PROBES_ENABLED?: string;
  PROBE_AGENT_URL?: string;
  PROBE_SHARED_SECRET?: string;
}

type ProbeSender = (
  endpoint: string,
  secret: string,
  job: ProbeJob,
  options?: { fetcher?: typeof fetch; now?: () => number; requestTimeoutMs?: number }
) => Promise<ProbeResult>;

export interface ProbeDispatchOptions {
  now?: Date | string;
  clock?: () => Date;
  limit?: number;
  perOrganizationLimit?: number;
  concurrency?: number;
  retryDelayMs?: number;
  probe?: ProbeSender;
}

export interface ProbeDispatchSummary {
  skipped: boolean;
  reason?: "PROBES_DISABLED" | "PROBE_AGENT_CONFIGURATION_MISSING" | "PROBE_AGENT_CONFIGURATION_INVALID";
  claimed: number;
  finalized: number;
  deferred: number;
  stale: number;
  dispatchErrors: number;
}

const DEFAULT_BATCH_LIMIT = 10;
const MAX_BATCH_LIMIT = 15;
const DEFAULT_ORGANIZATION_LIMIT = 2;
const DEFAULT_CONCURRENCY = 5;
// Leave one slot below Cloudflare's six simultaneous outbound-connection limit.
const MAX_CONCURRENCY = 5;
const DEFAULT_RETRY_DELAY_MS = 30_000;
const MIN_RETRY_DELAY_MS = 5_000;
const MAX_RETRY_DELAY_MS = 300_000;

function toDate(value: Date | string | undefined): Date {
  const date = value instanceof Date ? new Date(value.getTime()) : value === undefined ? new Date() : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("SCHEDULER_NOW_INVALID");
  return date;
}

function validProbeResult(result: ProbeResult): boolean {
  return Boolean(result && typeof result.isUp === "boolean" &&
    (result.statusCode === null || (Number.isInteger(result.statusCode) && result.statusCode >= 100 && result.statusCode <= 599)) &&
    Number.isInteger(result.responseTimeMs) && result.responseTimeMs >= 0 && result.responseTimeMs <= 30_000 &&
    (result.errorCode === null || (typeof result.errorCode === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(result.errorCode))) &&
    Number.isInteger(result.redirectCount) && result.redirectCount >= 0 && result.redirectCount <= 3 &&
    (result.isUp ? result.statusCode !== null && result.errorCode === null : result.errorCode !== null));
}

function emptySummary(reason?: ProbeDispatchSummary["reason"]): ProbeDispatchSummary {
  return {
    skipped: Boolean(reason),
    ...(reason ? { reason } : {}),
    claimed: 0,
    finalized: 0,
    deferred: 0,
    stale: 0,
    dispatchErrors: 0
  };
}

export function probeDispatchDisabledReason(env: ProbeDispatchEnv): ProbeDispatchSummary["reason"] | undefined {
  if (env.PROBES_ENABLED !== "true") return "PROBES_DISABLED";
  const endpoint = env.PROBE_AGENT_URL;
  const secret = env.PROBE_SHARED_SECRET;
  if (typeof endpoint !== "string" || typeof secret !== "string" ||
      new TextEncoder().encode(secret).byteLength < 32) {
    return "PROBE_AGENT_CONFIGURATION_MISSING";
  }
  try {
    validateProbeAgentEndpoint(endpoint);
  } catch {
    return "PROBE_AGENT_CONFIGURATION_INVALID";
  }
  return undefined;
}

/** True only when the operator has explicitly enabled probes and supplied valid agent credentials. */
export function isProbeExecutionEnabled(env: ProbeDispatchEnv): boolean {
  return probeDispatchDisabledReason(env) === undefined;
}

/**
 * Dispatch a bounded, workspace-fair batch to the separately hosted probe
 * agent. Configuration is checked before claiming work. Agent/network failures
 * defer the monitor without recording a false customer outage; only a valid,
 * signed and schema-checked result can advance check history or incidents.
 */
export async function dispatchDueMonitors(
  env: ProbeDispatchEnv,
  options: ProbeDispatchOptions = {}
): Promise<ProbeDispatchSummary> {
  const disabledReason = probeDispatchDisabledReason(env);
  if (disabledReason) return emptySummary(disabledReason);

  const endpoint = env.PROBE_AGENT_URL as string;
  const secret = env.PROBE_SHARED_SECRET as string;

  const now = toDate(options.now);
  const limit = options.limit ?? DEFAULT_BATCH_LIMIT;
  const perOrganizationLimit = options.perOrganizationLimit ?? DEFAULT_ORGANIZATION_LIMIT;
  const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
  const retryDelayMs = options.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_BATCH_LIMIT) throw new Error("SCHEDULER_LIMIT_INVALID");
  if (!Number.isInteger(perOrganizationLimit) || perOrganizationLimit < 1 || perOrganizationLimit > 10) {
    throw new Error("SCHEDULER_ORGANIZATION_LIMIT_INVALID");
  }
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > MAX_CONCURRENCY) {
    throw new Error("SCHEDULER_CONCURRENCY_INVALID");
  }
  if (!Number.isInteger(retryDelayMs) || retryDelayMs < MIN_RETRY_DELAY_MS || retryDelayMs > MAX_RETRY_DELAY_MS) {
    throw new Error("SCHEDULER_RETRY_DELAY_INVALID");
  }

  const claimed = await claimDueMonitors(env.DB, {
    now,
    limit,
    perOrganizationLimit,
    leaseMs: 180_000,
    token: crypto.randomUUID()
  });
  const summary: ProbeDispatchSummary = { ...emptySummary(), claimed: claimed.length };
  if (claimed.length === 0) return summary;

  const probe = options.probe ?? sendProbeJob;
  const clock = options.clock ?? (() => new Date());

  async function defer(monitor: ClaimedMonitor): Promise<void> {
    try {
      const retryAt = new Date(toDate(clock()).getTime() + retryDelayMs);
      if (await deferMonitorClaim(env.DB, monitor.id, monitor.leaseToken, retryAt)) summary.deferred += 1;
      else summary.stale += 1;
    } catch {
      summary.dispatchErrors += 1;
    }
  }

  async function processOne(monitor: ClaimedMonitor): Promise<void> {
    const method = monitor.method === "HEAD" || monitor.method === "GET" ? monitor.method : null;
    if (!method || !Number.isInteger(monitor.expectedStatus) || monitor.expectedStatus < 100 ||
        monitor.expectedStatus > 599 || !Number.isInteger(monitor.intervalSeconds) ||
        monitor.intervalSeconds < 60 || monitor.intervalSeconds > 3600 ||
        !Number.isInteger(monitor.timeoutMs) || monitor.timeoutMs < 1_000 || monitor.timeoutMs > 30_000) {
      await defer(monitor);
      return;
    }

    const job: ProbeJob = {
      targetUrl: monitor.targetUrl,
      method,
      expectedStatus: monitor.expectedStatus,
      timeoutMs: monitor.timeoutMs,
      // Redirects remain disabled until monitor-level redirect policy is
      // persisted and exposed in the create/edit workflow.
      maxRedirects: 0
    };

    try {
      const result = await probe(endpoint, secret, job, {
        requestTimeoutMs: Math.min(35_000, monitor.timeoutMs + 4_000)
      });
      if (!validProbeResult(result)) throw new Error("PROBE_AGENT_INVALID_RESPONSE");

      const checkedAt = toDate(clock());
      const nextCheckAt = new Date(checkedAt.getTime() + monitor.intervalSeconds * 1000);
      const finalized = await finalizeMonitorCheck(env.DB, {
        monitorId: monitor.id,
        leaseToken: monitor.leaseToken,
        checkedAt,
        nextCheckAt,
        isUp: result.isUp,
        statusCode: result.statusCode,
        responseTimeMs: result.responseTimeMs,
        errorCode: result.errorCode,
        checkId: crypto.randomUUID()
      });
      if (finalized) summary.finalized += 1;
      else summary.stale += 1;
    } catch {
      // Agent availability, signature, transport and response failures are
      // infrastructure failures. They must not be counted as target downtime.
      await defer(monitor);
    }
  }

  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < claimed.length) {
      const index = cursor++;
      await processOne(claimed[index]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, claimed.length) }, () => worker()));
  return summary;
}
