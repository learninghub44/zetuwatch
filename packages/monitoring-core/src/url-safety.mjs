import { isIpv4Address, isPublicIpAddress } from "./ip-address.mjs";

const BLOCKED_HOSTS = new Set(["localhost", "localhost.localdomain", "metadata.google.internal", "metadata"]);
const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".test", ".invalid", ".example"];

export function validateMonitorUrl(input) {
  if (typeof input !== "string" || input.length === 0) throw new Error("INVALID_URL");
  if (input.length > 2048) throw new Error("URL_TOO_LONG");
  let url;
  try { url = new URL(input); } catch { throw new Error("INVALID_URL"); }
  if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("UNSUPPORTED_PROTOCOL");
  if (url.username || url.password) throw new Error("URL_CREDENTIALS_NOT_ALLOWED");
  const defaultPort = url.protocol === "https:" ? "443" : "80";
  if (url.port && url.port !== defaultPort) throw new Error("PORT_NOT_ALLOWED");
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!host || BLOCKED_HOSTS.has(host) || BLOCKED_SUFFIXES.some(suffix => host.endsWith(suffix))) {
    throw new Error("HOST_NOT_ALLOWED");
  }
  if (host.includes(":")) throw new Error("IP_NOT_ALLOWED");
  if (isIpv4Address(host) && !isPublicIpAddress(host)) throw new Error("IP_NOT_ALLOWED");
  if (/^[0-9.]+$/.test(host) && !isIpv4Address(host)) throw new Error("IP_NOT_ALLOWED");
  if (!host.includes(".") || host.length > 253) throw new Error("HOST_NOT_ALLOWED");
  url.hostname = host;
  return url;
}
