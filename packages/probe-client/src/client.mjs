const encoder = new TextEncoder();
const MAX_RESPONSE_BYTES = 4 * 1024;

function toHex(bytes) {
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, "0")).join("");
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function normalizeJob(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("PROBE_JOB_INVALID");
  const allowed = new Set(["targetUrl", "method", "expectedStatus", "timeoutMs", "maxRedirects"]);
  if (Object.keys(input).some(key => !allowed.has(key))) throw new Error("PROBE_JOB_INVALID");
  const method = input.method ?? "GET";
  const expectedStatus = input.expectedStatus ?? 200;
  const timeoutMs = input.timeoutMs ?? 5_000;
  const maxRedirects = input.maxRedirects ?? 0;
  if (typeof input.targetUrl !== "string" || input.targetUrl.length < 8 || input.targetUrl.length > 2048) throw new Error("PROBE_JOB_INVALID");
  if (method !== "GET" && method !== "HEAD") throw new Error("PROBE_METHOD_NOT_ALLOWED");
  if (!Number.isInteger(expectedStatus) || expectedStatus < 100 || expectedStatus > 599) throw new Error("PROBE_STATUS_INVALID");
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 30_000) throw new Error("PROBE_TIMEOUT_INVALID");
  if (!Number.isInteger(maxRedirects) || maxRedirects < 0 || maxRedirects > 3) throw new Error("PROBE_REDIRECT_LIMIT_INVALID");
  return { targetUrl: input.targetUrl, method, expectedStatus, timeoutMs, maxRedirects };
}

async function readLimitedJson(response) {
  if (!response.body) throw new Error("PROBE_AGENT_INVALID_RESPONSE");
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      total += item.value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new Error("PROBE_AGENT_RESPONSE_TOO_LARGE");
      }
      chunks.push(item.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder().decode(bytes)); }
  catch { throw new Error("PROBE_AGENT_INVALID_RESPONSE"); }
}

export function validateProbeAgentEndpoint(endpoint) {
  let url;
  try { url = new URL(endpoint); } catch { throw new Error("PROBE_AGENT_ENDPOINT_INVALID"); }
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search || url.pathname !== "/v1/probe" || (url.port && url.port !== "443")) {
    throw new Error("PROBE_AGENT_ENDPOINT_INVALID");
  }
  return url;
}

export async function signProbePayload(secret, timestamp, nonce, body) {
  if (typeof secret !== "string" || encoder.encode(secret).byteLength < 32) throw new Error("PROBE_AGENT_SECRET_REQUIRED");
  const digest = toHex(await crypto.subtle.digest("SHA-256", encoder.encode(body)));
  const canonical = `v1\n${timestamp}\n${nonce}\n${digest}`;
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(await crypto.subtle.sign("HMAC", key, encoder.encode(canonical)));
}

export async function sendProbeJob(endpoint, secret, input, options = {}) {
  const target = validateProbeAgentEndpoint(endpoint);
  const job = normalizeJob(input);
  const fetcher = options.fetcher ?? fetch;
  const now = options.now ?? Date.now;
  const timestamp = String(Math.floor(now() / 1000));
  const nonce = toBase64Url(crypto.getRandomValues(new Uint8Array(24)));
  const body = JSON.stringify(job);
  const signature = await signProbePayload(secret, timestamp, nonce, body);
  const requestTimeoutMs = options.requestTimeoutMs ?? job.timeoutMs + 4_000;
  if (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 1_000 || requestTimeoutMs > 35_000) {
    throw new Error("PROBE_AGENT_TIMEOUT_INVALID");
  }

  let response;
  try {
    response = await fetcher(target.href, {
      method: "POST",
      redirect: "error",
      cache: "no-store",
      credentials: "omit",
      signal: AbortSignal.timeout(requestTimeoutMs),
      headers: {
        "content-type": "application/json",
        "x-zw-timestamp": timestamp,
        "x-zw-nonce": nonce,
        "x-zw-signature": signature
      },
      body
    });
  } catch { throw new Error("PROBE_AGENT_UNAVAILABLE"); }

  if (!response.ok) throw new Error(response.status === 401 || response.status === 409 ? "PROBE_AGENT_AUTH_FAILED" : "PROBE_AGENT_UNAVAILABLE");
  if (!(response.headers.get("content-type") || "").toLowerCase().includes("application/json")) throw new Error("PROBE_AGENT_INVALID_RESPONSE");
  const payload = await readLimitedJson(response);
  const result = payload?.result;
  if (!result || typeof result.isUp !== "boolean" ||
      !(result.statusCode === null || (Number.isInteger(result.statusCode) && result.statusCode >= 100 && result.statusCode <= 599)) ||
      !Number.isInteger(result.responseTimeMs) || result.responseTimeMs < 0 || result.responseTimeMs > job.timeoutMs + 5_000 ||
      !(result.errorCode === null || (typeof result.errorCode === "string" && /^[A-Z_]{1,48}$/.test(result.errorCode))) ||
      !Number.isInteger(result.redirectCount) || result.redirectCount < 0 || result.redirectCount > 3 ||
      (result.isUp && (result.statusCode === null || result.errorCode !== null)) ||
      (!result.isUp && result.errorCode === null)) {
    throw new Error("PROBE_AGENT_INVALID_RESPONSE");
  }
  return result;
}
