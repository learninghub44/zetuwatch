import { isIpv4Address, isPublicIpAddress } from "./ip-address.mjs";

const BLOCKED_HOSTS = new Set(["localhost", "localhost.localdomain", "metadata.google.internal", "metadata"]);
const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".test", ".invalid", ".example"];
const NUMERIC_HOST = /^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*$/i;

function rawAuthorityHost(input) {
  const match = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(input);
  if (!match) throw new Error("INVALID_URL");
  const authority = match[1];
  if (authority.includes("@")) throw new Error("URL_CREDENTIALS_NOT_ALLOWED");

  if (authority.startsWith("[")) {
    const closingBracket = authority.indexOf("]");
    if (closingBracket < 0) throw new Error("INVALID_URL");
    return authority.slice(1, closingBracket);
  }

  const portSeparator = authority.lastIndexOf(":");
  return portSeparator < 0 ? authority : authority.slice(0, portSeparator);
}

export function validateMonitorUrl(input) {
  if (typeof input !== "string" || input.length === 0) throw new Error("INVALID_URL");
  if (input.length > 2048) throw new Error("URL_TOO_LONG");
  // WHATWG URL parsing strips ASCII tabs/newlines before parsing. Reject
  // control characters first so raw-host validation sees the original input.
  if (/[\u0000-\u001f\u007f]/.test(input)) throw new Error("INVALID_URL");

  const rawHost = rawAuthorityHost(input).toLowerCase().replace(/\.$/, "");
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

  // WHATWG URL parsing canonicalizes legacy IPv4 spellings such as 127.1,
  // integer-only addresses and hexadecimal/octal forms. Reject those spellings
  // before they can be mistaken for an ordinary hostname or canonical IP.
  if (NUMERIC_HOST.test(rawHost) && rawHost !== host) throw new Error("IP_NOT_ALLOWED");

  if (host.includes(":")) throw new Error("IP_NOT_ALLOWED");
  if (isIpv4Address(host) && !isPublicIpAddress(host)) throw new Error("IP_NOT_ALLOWED");
  if (/^[0-9.]+$/.test(host) && !isIpv4Address(host)) throw new Error("IP_NOT_ALLOWED");
  if (!host.includes(".") || host.length > 253) throw new Error("HOST_NOT_ALLOWED");

  url.hostname = host;
  return url;
}
