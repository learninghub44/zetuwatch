import { assertPublicDnsAnswers, isIpv4Address } from "./ip-address";

const DNS_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const MAX_DNS_RESPONSE_BYTES = 16 * 1024;
const MAX_DNS_TIMEOUT_MS = 5_000;

export type DnsFetcher = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

interface DnsJsonAnswer {
  type?: number;
  data?: unknown;
}

interface DnsJsonResponse {
  Status?: number;
  TC?: boolean;
  Answer?: DnsJsonAnswer[];
}

function normalizeHostname(input: string): string {
  if (typeof input !== "string" || input.length === 0 || input.length > 254) {
    throw new Error("DNS_HOST_NOT_ALLOWED");
  }
  const hostname = input.toLowerCase().replace(/\.$/, "");
  if (
    !hostname ||
    hostname.length > 253 ||
    !hostname.includes(".") ||
    hostname.includes(":") ||
    /^[0-9.]+$/.test(hostname) ||
    isIpv4Address(hostname) ||
    [".localhost", ".local", ".internal", ".test", ".invalid", ".example"].some((suffix) => hostname.endsWith(suffix)) ||
    hostname === "localhost" ||
    hostname === "metadata" ||
    hostname === "metadata.google.internal"
  ) {
    throw new Error("DNS_HOST_NOT_ALLOWED");
  }

  const labels = hostname.split(".");
  if (labels.some((label) =>
    label.length === 0 ||
    label.length > 63 ||
    !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  )) {
    throw new Error("DNS_HOST_NOT_ALLOWED");
  }
  return hostname;
}

async function readLimitedText(response: Response): Promise<string> {
  if (!response.body) throw new Error("DNS_INVALID_RESPONSE");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const result = await reader.read();
      if (result.done) break;
      totalBytes += result.value.byteLength;
      if (totalBytes > MAX_DNS_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new Error("DNS_RESPONSE_TOO_LARGE");
      }
      chunks.push(decoder.decode(result.value, { stream: true }));
    }
    chunks.push(decoder.decode());
    return chunks.join("");
  } finally {
    reader.releaseLock();
  }
}

async function queryAddressRecords(
  hostname: string,
  recordType: 1 | 28,
  fetcher: DnsFetcher,
  timeoutMs: number
): Promise<string[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const requestUrl = new URL(DNS_ENDPOINT);
    requestUrl.searchParams.set("name", hostname);
    requestUrl.searchParams.set("type", String(recordType));

    const response = await fetcher(requestUrl, {
      method: "GET",
      headers: { accept: "application/dns-json" },
      redirect: "error",
      signal: controller.signal
    });
    if (!response.ok) throw new Error("DNS_HTTP_ERROR");
    if (!(response.headers.get("content-type") || "").toLowerCase().includes("application/dns-json")) {
      throw new Error("DNS_INVALID_CONTENT_TYPE");
    }

    let payload: DnsJsonResponse;
    try {
      payload = JSON.parse(await readLimitedText(response)) as DnsJsonResponse;
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("DNS_")) throw error;
      throw new Error("DNS_INVALID_RESPONSE");
    }

    if (!payload || payload.Status !== 0) throw new Error("DNS_LOOKUP_FAILED");
    if (payload.TC === true) throw new Error("DNS_TRUNCATED_RESPONSE");
    if (payload.Answer !== undefined && !Array.isArray(payload.Answer)) {
      throw new Error("DNS_INVALID_RESPONSE");
    }

    const answers = payload.Answer || [];
    if (answers.some((answer) =>
      !answer ||
      typeof answer !== "object" ||
      typeof answer.type !== "number" ||
      !Number.isInteger(answer.type) ||
      typeof answer.data !== "string"
    )) {
      throw new Error("DNS_INVALID_RESPONSE");
    }
    return answers
      .filter((answer) => answer.type === recordType)
      .map((answer) => answer.data as string);
  } catch (error) {
    if (controller.signal.aborted) throw new Error("DNS_TIMEOUT");
    if (error instanceof Error && error.message.startsWith("DNS_")) throw error;
    throw new Error("DNS_LOOKUP_FAILED");
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Resolve a DNS hostname through Cloudflare's documented DNS-over-HTTPS JSON
 * endpoint. Both A and AAAA answers are collected and the entire set is
 * rejected if any answer is not globally routable.
 *
 * This returns validated candidates only. It does not pin a connection and
 * must not be treated as protection from DNS rebinding until the transport
 * connects to one of these exact addresses without resolving the hostname
 * again.
 */
export async function resolvePublicHostname(
  input: string,
  options: { fetcher?: DnsFetcher; timeoutMs?: number } = {}
): Promise<string[]> {
  const hostname = normalizeHostname(input);
  const timeoutMs = options.timeoutMs ?? 2_500;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > MAX_DNS_TIMEOUT_MS) {
    throw new Error("DNS_TIMEOUT_INVALID");
  }

  const fetcher = options.fetcher ?? fetch;
  const [ipv4, ipv6] = await Promise.all([
    queryAddressRecords(hostname, 1, fetcher, timeoutMs),
    queryAddressRecords(hostname, 28, fetcher, timeoutMs)
  ]);
  return assertPublicDnsAnswers([...ipv4, ...ipv6]);
}
