/**
 * Probe execution is intentionally fail-closed.
 *
 * Cloudflare Workers fetch() does not let this package pin a validated DNS
 * answer to the actual outbound socket. Calling fetch() directly for a
 * customer-controlled hostname would leave a DNS-rebinding/SSRF gap.
 *
 * Do not replace this guard with ordinary fetch() until a dedicated egress
 * service can resolve and validate every A/AAAA answer, connect to the
 * validated address, validate every redirect hop, and enforce response caps.
 */
export interface HttpProbeResult {
  isUp: boolean;
  statusCode: number | null;
  responseTimeMs: number;
  errorCode: string | null;
}

export async function runHttpProbe(
  _target: string,
  _method = "GET",
  _expectedStatus = 200,
  _timeoutMs = 10_000
): Promise<HttpProbeResult> {
  throw new Error("PROBE_EGRESS_NOT_HARDENED");
}
