/**
 * Conservative, dependency-free public IP policy shared by the Worker and the
 * dedicated Node probe agent. A public classification is not sufficient by
 * itself: callers must pin the selected address to the actual connection.
 */
function parseIpv4(input) {
  const parts = input.split(".");
  if (parts.length !== 4) return null;
  const octets = [];
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return null;
    const value = Number(part);
    if (value > 255) return null;
    octets.push(value);
  }
  return Uint8Array.from(octets);
}

function parseIpv6(input) {
  if (!input || input.includes("%")) return null;
  let value = input.toLowerCase();
  if (value.includes(".")) {
    const separator = value.lastIndexOf(":");
    if (separator < 0) return null;
    const ipv4 = parseIpv4(value.slice(separator + 1));
    if (!ipv4) return null;
    const high = ((ipv4[0] << 8) | ipv4[1]).toString(16);
    const low = ((ipv4[2] << 8) | ipv4[3]).toString(16);
    value = value.slice(0, separator + 1) + high + ":" + low;
  }
  const compression = value.indexOf("::");
  if (compression !== value.lastIndexOf("::")) return null;
  let groups;
  if (compression >= 0) {
    const leftText = value.slice(0, compression);
    const rightText = value.slice(compression + 2);
    const left = leftText ? leftText.split(":") : [];
    const right = rightText ? rightText.split(":") : [];
    if (left.some(part => !part) || right.some(part => !part)) return null;
    const zeroGroups = 8 - left.length - right.length;
    if (zeroGroups < 1) return null;
    groups = [...left, ...Array.from({ length: zeroGroups }, () => "0"), ...right];
  } else {
    if (value.startsWith(":") || value.endsWith(":")) return null;
    groups = value.split(":");
    if (groups.length !== 8) return null;
  }
  if (groups.length !== 8 || groups.some(part => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  const bytes = new Uint8Array(16);
  groups.forEach((part, index) => {
    const word = Number.parseInt(part, 16);
    bytes[index * 2] = word >> 8;
    bytes[index * 2 + 1] = word & 0xff;
  });
  return bytes;
}

function inCidr(address, cidr) {
  if (address.length !== cidr.network.length) return false;
  const fullBytes = Math.floor(cidr.prefix / 8);
  const remainingBits = cidr.prefix % 8;
  for (let index = 0; index < fullBytes; index += 1) {
    if (address[index] !== cidr.network[index]) return false;
  }
  if (remainingBits === 0) return true;
  const mask = (0xff << (8 - remainingBits)) & 0xff;
  return (address[fullBytes] & mask) === (cidr.network[fullBytes] & mask);
}

const IPV4_NON_PUBLIC = [
  { network: [0, 0, 0, 0], prefix: 8 },
  { network: [10, 0, 0, 0], prefix: 8 },
  { network: [100, 64, 0, 0], prefix: 10 },
  { network: [127, 0, 0, 0], prefix: 8 },
  { network: [169, 254, 0, 0], prefix: 16 },
  { network: [172, 16, 0, 0], prefix: 12 },
  { network: [192, 0, 0, 0], prefix: 24 },
  { network: [192, 0, 2, 0], prefix: 24 },
  { network: [192, 88, 99, 0], prefix: 24 },
  { network: [192, 168, 0, 0], prefix: 16 },
  { network: [198, 18, 0, 0], prefix: 15 },
  { network: [198, 51, 100, 0], prefix: 24 },
  { network: [203, 0, 113, 0], prefix: 24 },
  { network: [224, 0, 0, 0], prefix: 4 },
  { network: [240, 0, 0, 0], prefix: 4 }
];
const IPV6_GLOBAL_UNICAST = {
  network: [0x20, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  prefix: 3
};
const IPV6_NON_PUBLIC = [
  { network: [0x20, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], prefix: 23 },
  { network: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], prefix: 32 },
  { network: [0x20, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], prefix: 16 },
  { network: [0x3f, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], prefix: 20 }
];

export function isIpv4Address(input) {
  return typeof input === "string" && parseIpv4(input) !== null;
}

export function isPublicIpAddress(input) {
  if (typeof input !== "string") return false;
  const ipv4 = parseIpv4(input);
  if (ipv4) return !IPV4_NON_PUBLIC.some(range => inCidr(ipv4, range));
  const ipv6 = parseIpv6(input);
  if (!ipv6 || !inCidr(ipv6, IPV6_GLOBAL_UNICAST)) return false;
  return !IPV6_NON_PUBLIC.some(range => inCidr(ipv6, range));
}

export function assertPublicDnsAnswers(addresses) {
  if (!Array.isArray(addresses) || addresses.length === 0) throw new Error("DNS_NO_ADDRESSES");
  if (addresses.length > 16) throw new Error("DNS_TOO_MANY_ADDRESSES");
  const normalized = addresses.map(address => typeof address === "string" ? address.trim() : "");
  if (normalized.some(address => !address || !isPublicIpAddress(address))) throw new Error("DNS_NON_PUBLIC_ADDRESS");
  return [...new Set(normalized)];
}
