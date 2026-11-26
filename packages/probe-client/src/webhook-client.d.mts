export interface WebhookJob {
  destinationUrl: string;
  eventId: string;
  payload: string;
  signatureHeader: string;
}
export interface WebhookResult {
  delivered: boolean;
  responseStatus: number | null;
  errorCode: string | null;
  retryAfterSeconds: number | null;
}
export function sendWebhookJob(
  endpoint: string,
  secret: string,
  job: WebhookJob,
  options?: { fetcher?: typeof fetch; now?: () => number; requestTimeoutMs?: number }
): Promise<WebhookResult>;
