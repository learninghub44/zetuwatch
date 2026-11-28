export interface ProbeJob {
  targetUrl: string;
  method?: "GET" | "HEAD";
  expectedStatus?: number;
  timeoutMs?: number;
  maxRedirects?: number;
}
export interface ProbeResult {
  isUp: boolean;
  statusCode: number | null;
  responseTimeMs: number;
  errorCode: string | null;
  redirectCount: number;
}
export function validateProbeAgentEndpoint(endpoint: string): URL;
export function signProbePayload(secret: string, timestamp: string, nonce: string, body: string): Promise<string>;
export function verifyProbePayload(secret: string, timestamp: string, nonce: string, body: string, signature: string): Promise<boolean>;
export function sendProbeJob(
  endpoint: string,
  secret: string,
  job: ProbeJob,
  options?: { fetcher?: typeof fetch; now?: () => number; requestTimeoutMs?: number }
): Promise<ProbeResult>;
