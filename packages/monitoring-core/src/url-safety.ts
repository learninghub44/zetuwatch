import { isIpv4Address, isPublicIpAddress } from "./ip-address";

/**
 * Syntactic URL policy for customer-supplied HTTP monitors.
 *
 * This is only the first SSRF gate. Cloudflare Workers' ordinary fetch API
 * does not expose a DNS answer that can be pinned to the outbound connection.
 * Therefore this function deliberately does NOT claim to defeat DNS rebinding.
 * Production egress must validate every A/AAAA answer and bind the validated
 * address to the actual socket.
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

  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!host || BLOCKED_HOSTS.has(host) || BLOCKED_SUFFIXES.some((suffix) => host.endsWith(suffix))) {
    throw new Error("HOST_NOT_ALLOWED");
  }

  // IPv6 literals remain disabled until the runtime egress transport can
  // classify and pin IPv6 destinations. The shared classifier still validates
  // IPv6 DNS answers so the resolver layer can fail closed when added.
  if (host.includes(":")) throw new Error("IP_NOT_ALLOWED");
  if (isIpv4Address(host) && !isPublicIpAddress(host)) throw new Error("IP_NOT_ALLOWED");

  // WHATWG URL parsing normalizes many unusual IPv4 spellings to dotted form.
  // Reject numeric-looking hosts that did not normalize to a valid IPv4 value.
  if (/^[0-9.]+$/.test(host) && !isIpv4Address(host)) throw new Error("IP_NOT_ALLOWED");

  if (!host.includes(".") || host.length > 253) throw new Error("HOST_NOT_ALLOWED");
  return url;
}
