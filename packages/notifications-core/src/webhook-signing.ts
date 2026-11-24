import { createWebhookSecret } from "./webhook-secrets";

const encoder = new TextEncoder();
export const MAX_WEBHOOK_PAYLOAD_BYTES = 256 * 1024;
export const DEFAULT_WEBHOOK_TOLERANCE_SECONDS = 300;
const WEBHOOK_SECRET_PATTERN = /^whsec_[A-Za-z0-9_-]{43}$/;
const SIGNATURE_PATTERN = /^t=(0|[1-9][0-9]{0,11}),v1=([a-f0-9]{64})$/;

function ownedBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, value => value.toString(16).padStart(2, "0")).join("");
}

function fromHex(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function validSecret(secret: string): boolean {
  return typeof secret === "string" && WEBHOOK_SECRET_PATTERN.test(secret);
}

function validPayload(payload: string): boolean {
  return typeof payload === "string" && payload.length <= MAX_WEBHOOK_PAYLOAD_BYTES &&
    encoder.encode(payload).byteLength <= MAX_WEBHOOK_PAYLOAD_BYTES;
}

function validTimestamp(timestampSeconds: number): boolean {
  return Number.isSafeInteger(timestampSeconds) &&
    timestampSeconds >= 0 &&
    timestampSeconds <= 999_999_999_999;
}

async function importSigningKey(secret: string, usage: "sign" | "verify"): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    ownedBuffer(encoder.encode(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    [usage]
  );
}

/** Sign the exact UTF-8 request body; receivers must verify before parsing JSON. */
export async function signWebhookPayload(
  secret: string,
  payload: string,
  timestampSeconds = Math.floor(Date.now() / 1000)
): Promise<string> {
  if (!validSecret(secret)) throw new Error("WEBHOOK_SECRET_INVALID");
  if (!validPayload(payload)) throw new Error("WEBHOOK_PAYLOAD_TOO_LARGE");
  if (!validTimestamp(timestampSeconds)) throw new Error("WEBHOOK_TIMESTAMP_INVALID");

  const key = await importSigningKey(secret, "sign");
  const signedBytes = encoder.encode(String(timestampSeconds) + "." + payload);
  const signature = await crypto.subtle.sign("HMAC", key, ownedBuffer(signedBytes));
  return "t=" + timestampSeconds + ",v1=" + toHex(new Uint8Array(signature));
}

/** Verify timestamped HMAC-SHA256. Malformed, stale, future and oversized payloads fail closed. */
export async function verifyWebhookSignature(
  secret: string,
  payload: string,
  signatureHeader: string,
  nowSeconds = Math.floor(Date.now() / 1000),
  toleranceSeconds = DEFAULT_WEBHOOK_TOLERANCE_SECONDS
): Promise<boolean> {
  if (!validSecret(secret) || !validPayload(payload)) return false;
  if (!validTimestamp(nowSeconds) ||
      !Number.isInteger(toleranceSeconds) ||
      toleranceSeconds < 30 ||
      toleranceSeconds > 900) return false;

  const match = SIGNATURE_PATTERN.exec(signatureHeader);
  if (!match) return false;
  const timestampSeconds = Number(match[1]);
  if (!validTimestamp(timestampSeconds) ||
      Math.abs(nowSeconds - timestampSeconds) > toleranceSeconds) return false;

  try {
    const key = await importSigningKey(secret, "verify");
    const signature = fromHex(match[2]);
    const signedBytes = encoder.encode(String(timestampSeconds) + "." + payload);
    return await crypto.subtle.verify("HMAC", key, ownedBuffer(signature), ownedBuffer(signedBytes));
  } catch {
    return false;
  }
}

export { createWebhookSecret };
