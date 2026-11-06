/**
 * Syntactic URL policy for customer-supplied HTTP monitors.
 *
 * This is only the first SSRF gate. Cloudflare Workers' ordinary fetch API
 * does not expose a DNS answer that can be pinned to the outbound connection.
 * Therefore this function deliberately does NOT claim to defeat DNS rebinding.
 * Production egress must pass through a resolver/prober that validates every
 * A/AAAA answer and binds the validated address to the actual socket.
 */
const BLOCKED_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "metadata.google.internal",
  "metadata",
]);

const BLOCKED_SUFFIXES = [
  ".localhost",
  ".local",
  ".internal",
  ".test",
  ".invalid",
  ".example",
];

function isIpv4Literal(host: string): boolean {
  return /^\\d{1,3}(?:\\.\\d{1,3}){3}$/.test(host);
}

function isNonPublicIpv4(host: string): boolean {
  if (!isIpv4Literal(host)) return false;
  const octets = host.split(".").map(Number);
  if (octets.some((part) => part < 0 || part > 255)) return true;
  const [a, b, c] = octets;
  return (
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    a === 240
  );
}

export function validateMonitorUrl(input: string): URL {
  if (typeof input !== "string" || input.length === 0) throw new Error("INVALID_URL");
  if (input.length > 2048) throw new Error("URL_TOO_LONG");

  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new Error("INVALID_URL");
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("UNSUPPORTED_PROTOCOL");
  }
  if (url.username || url.password) throw new Error("URL_CREDENTIALS_NOT_ALLOWED");
  if (url.port && !["80", "443"].includes(url.port)) throw new Error("PORT_NOT_ALLOWED");

  const host = url.hostname.toLowerCase().replace(/^\\[|\\]$/g, "");
  if (!host || BLOCKED_HOSTS.has(host) || BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
    throw new Error("HOST_NOT_ALLOWED");
  }

  // Reject IPv6 literals until an egress implementation can classify and pin
  // resolved addresses. This also blocks IPv4-mapped IPv6 bypasses.
  if (host.includes(":")) throw new Error("IP_NOT_ALLOWED");
  if (isNonPublicIpv4(host)) throw new Error("IP_NOT_ALLOWED");

  // WHATWG URL parsing normalizes many unusual IPv4 spellings to dotted form.
  // Reject numeric-looking hosts that did not normalize to a valid IPv4 value.
  if (/^[0-9.]+$/.test(host) && !isIpv4Literal(host)) throw new Error("IP_NOT_ALLOWED");

  if (!host.includes(".") || host.length > 253) throw new Error("HOST_NOT_ALLOWED");
  return url;
}
