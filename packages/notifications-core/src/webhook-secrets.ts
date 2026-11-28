import { isBlockedHostname } from "../../monitoring-core/src/url-safety";

const encoder = new TextEncoder();
const ENCRYPTION_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;
export const WEBHOOK_ENCRYPTION_KEY_VERSION = 1;

export interface EncryptedWebhookValue {
  ciphertext: string;
  nonce: string;
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("WEBHOOK_ENCODING_INVALID");
  const standard = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = standard + "=".repeat((4 - standard.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function ownedBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function encryptionKeyBytes(value: string): Uint8Array {
  if (typeof value !== "string" || !ENCRYPTION_KEY_PATTERN.test(value)) {
    throw new Error("WEBHOOK_ENCRYPTION_KEY_INVALID");
  }
  const bytes = decodeBase64Url(value);
  if (bytes.byteLength !== 32) throw new Error("WEBHOOK_ENCRYPTION_KEY_INVALID");
  return bytes;
}

async function importEncryptionKey(value: string, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    ownedBuffer(encryptionKeyBytes(value)),
    { name: "AES-GCM" },
    false,
    [usage]
  );
}

function validContext(context: string): boolean {
  return typeof context === "string" && context.length >= 1 &&
    context.length <= 256 && !/[\u0000-\u001f\u007f]/.test(context);
}

/** Generate a 256-bit endpoint secret. The caller must display it once and encrypt it at rest. */
export function createWebhookSecret(): string {
  return "whsec_" + base64Url(crypto.getRandomValues(new Uint8Array(32)));
}

/**
 * Encrypt a URL or signing secret using AES-256-GCM. The context is authenticated
 * as additional data so ciphertext cannot be swapped between tenants, endpoints,
 * or fields. The caller supplies a 32-byte base64url Worker secret.
 */
export async function encryptWebhookValue(
  value: string,
  encryptionKey: string,
  context: string
): Promise<EncryptedWebhookValue> {
  if (typeof value !== "string" || value.length < 1 ||
      encoder.encode(value).byteLength > 4_096 || !validContext(context)) {
    throw new Error("WEBHOOK_VALUE_INVALID");
  }
  const key = await importEncryptionKey(encryptionKey, "encrypt");
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: ownedBuffer(nonce), additionalData: ownedBuffer(encoder.encode(context)), tagLength: 128 },
    key,
    ownedBuffer(encoder.encode(value))
  );
  return { ciphertext: base64Url(new Uint8Array(ciphertext)), nonce: base64Url(nonce) };
}

/** Decrypt only when the same tenant/endpoint/field context is supplied. */
export async function decryptWebhookValue(
  encrypted: EncryptedWebhookValue,
  encryptionKey: string,
  context: string
): Promise<string> {
  if (!encrypted || typeof encrypted.ciphertext !== "string" ||
      typeof encrypted.nonce !== "string" || encrypted.nonce.length !== 16 ||
      encrypted.ciphertext.length < 23 || encrypted.ciphertext.length > 5_483 ||
      !validContext(context)) {
    throw new Error("WEBHOOK_CIPHERTEXT_INVALID");
  }
  const nonce = decodeBase64Url(encrypted.nonce);
  const ciphertext = decodeBase64Url(encrypted.ciphertext);
  if (nonce.byteLength !== 12 || ciphertext.byteLength < 17 || ciphertext.byteLength > 4_112) {
    throw new Error("WEBHOOK_CIPHERTEXT_INVALID");
  }
  try {
    const key = await importEncryptionKey(encryptionKey, "decrypt");
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ownedBuffer(nonce), additionalData: ownedBuffer(encoder.encode(context)), tagLength: 128 },
      key,
      ownedBuffer(ciphertext)
    );
    return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } catch {
    throw new Error("WEBHOOK_DECRYPT_FAILED");
  }
}

/**
 * Validate destination syntax only. This function performs no DNS lookup and
 * makes no network request; delivery must still validate and pin every DNS hop.
 */
export function normalizeWebhookDestination(value: unknown): { url: string; hostname: string } {
  if (typeof value !== "string" || value.length < 1 || value.length > 2_048 ||
      /[\u0000-\u001f\u007f]/.test(value) || value.includes("#")) {
    throw new Error("WEBHOOK_URL_INVALID");
  }
  let parsed: URL;
  try { parsed = new URL(value.trim()); } catch { throw new Error("WEBHOOK_URL_INVALID"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password ||
      (parsed.port !== "" && parsed.port !== "443")) {
    throw new Error("WEBHOOK_URL_POLICY_REJECTED");
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if (!hostname || hostname.startsWith("[") || hostname.includes(":") ||
      /^\d+(?:\.\d+){0,3}$/.test(hostname) || !hostname.includes(".") ||
      isBlockedHostname(hostname)) {
    throw new Error("WEBHOOK_HOST_POLICY_REJECTED");
  }
  const labels = hostname.split(".");
  if (hostname.length > 253 || labels.some(label =>
    label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  )) {
    throw new Error("WEBHOOK_HOST_INVALID");
  }

  parsed.hostname = hostname;
  const url = parsed.toString();
  if (url.length > 2_048) throw new Error("WEBHOOK_URL_INVALID");
  return { url, hostname };
}
