/**
 * Conservative first-pass URL validation.
 *
 * IMPORTANT: This does not resolve DNS and is not sufficient on its own to
 * protect against SSRF or DNS rebinding. Production probes must resolve and
 * validate all destination IPs and re-check every redirect hop.
 */
const BLOCKED_HOSTS = new Set(["localhost", "localhost.localdomain", "metadata.google.internal"]);

function isPrivateIpv4(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return false;
  const nums = parts.map(Number);
  if (nums.some((n) => n < 0 || n > 255)) return true;
  const [a, b] = nums;
  return a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224;
}

export function validateMonitorUrl(input: string): URL {
  if (input.length > 2048) throw new Error("URL_TOO_LONG");
  let url: URL;
  try { url = new URL(input); } catch { throw new Error("INVALID_URL"); }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("UNSUPPORTED_PROTOCOL");
  if (url.username || url.password) throw new Error("URL_CREDENTIALS_NOT_ALLOWED");
  if (url.port && !["80", "443"].includes(url.port)) throw new Error("PORT_NOT_ALLOWED");
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!host || BLOCKED_HOSTS.has(host) || host.endsWith(".localhost") || host.endsWith(".local")) {
    throw new Error("HOST_NOT_ALLOWED");
  }
  if (isPrivateIpv4(host) || host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80:")) {
    throw new Error("IP_NOT_ALLOWED");
  }
  return url;
}
