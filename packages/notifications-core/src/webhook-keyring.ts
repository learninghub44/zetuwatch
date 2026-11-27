const KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const KEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
export const LEGACY_WEBHOOK_ENCRYPTION_KEY_ID = "v1";

export interface WebhookKeyringEnvironment {
  WEBHOOK_ENCRYPTION_KEY?: string;
  WEBHOOK_ENCRYPTION_KEY_ID?: string;
  WEBHOOK_ENCRYPTION_KEY_PREVIOUS?: string;
  WEBHOOK_ENCRYPTION_KEY_PREVIOUS_ID?: string;
}

export interface WebhookEncryptionKey {
  id: string;
  value: string;
}

export interface WebhookKeyring {
  current: WebhookEncryptionKey;
  previous?: WebhookEncryptionKey;
}

function validKey(value: string): boolean {
  if (!KEY_PATTERN.test(value)) return false;
  try {
    const standard = value.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(standard + "=");
    return binary.length === 32;
  } catch {
    return false;
  }
}

function validKeyId(value: string): boolean {
  return KEY_ID_PATTERN.test(value);
}

/**
 * Read the active and optional previous master key. The previous key is
 * decrypt-only: every new value is encrypted with current. Existing installs
 * default to key id "v1" so their original AES-GCM AAD remains compatible.
 */
export function readWebhookKeyring(env: WebhookKeyringEnvironment): WebhookKeyring {
  const currentValue = env.WEBHOOK_ENCRYPTION_KEY;
  if (!currentValue) throw new Error("WEBHOOK_ENCRYPTION_KEY_MISSING");
  if (!validKey(currentValue)) throw new Error("WEBHOOK_ENCRYPTION_KEY_INVALID");

  const currentId = env.WEBHOOK_ENCRYPTION_KEY_ID?.trim() || LEGACY_WEBHOOK_ENCRYPTION_KEY_ID;
  if (!validKeyId(currentId)) throw new Error("WEBHOOK_ENCRYPTION_KEY_ID_INVALID");

  const previousValue = env.WEBHOOK_ENCRYPTION_KEY_PREVIOUS;
  const configuredPreviousId = env.WEBHOOK_ENCRYPTION_KEY_PREVIOUS_ID?.trim();
  if (configuredPreviousId && !previousValue) {
    throw new Error("WEBHOOK_PREVIOUS_KEY_ID_WITHOUT_KEY");
  }

  let previous: WebhookEncryptionKey | undefined;
  if (previousValue) {
    if (!validKey(previousValue)) throw new Error("WEBHOOK_ENCRYPTION_KEY_PREVIOUS_INVALID");
    const previousId = configuredPreviousId || LEGACY_WEBHOOK_ENCRYPTION_KEY_ID;
    if (!validKeyId(previousId)) throw new Error("WEBHOOK_ENCRYPTION_KEY_PREVIOUS_ID_INVALID");
    if (previousId === currentId) throw new Error("WEBHOOK_ENCRYPTION_KEY_IDS_MUST_DIFFER");
    previous = { id: previousId, value: previousValue };
  }

  return {
    current: { id: currentId, value: currentValue },
    ...(previous ? { previous } : {})
  };
}

/** Resolve a stored key id without ever falling back to the current key. */
export function getWebhookEncryptionKey(
  keyring: WebhookKeyring,
  keyId: string
): WebhookEncryptionKey {
  if (keyring.current.id === keyId) return keyring.current;
  if (keyring.previous?.id === keyId) return keyring.previous;
  throw new Error("WEBHOOK_ENCRYPTION_KEY_ID_UNAVAILABLE");
}

/**
 * Preserve the exact legacy context for v1 ciphertext. All later key ids are
 * included in authenticated additional data, preventing key-id substitution.
 */
export function webhookEncryptionContext(
  formatVersion: number,
  keyId: string,
  organizationId: string,
  endpointId: string,
  field: "url" | "secret"
): string {
  if (!Number.isInteger(formatVersion) || formatVersion < 1 || formatVersion > 99 ||
      !validKeyId(keyId) ||
      !organizationId || organizationId.length > 128 ||
      !endpointId || endpointId.length > 128 ||
      /[\u0000-\u001f\u007f]/.test(organizationId + endpointId)) {
    throw new Error("WEBHOOK_ENCRYPTION_CONTEXT_INVALID");
  }
  if (keyId === LEGACY_WEBHOOK_ENCRYPTION_KEY_ID) {
    return `zetuwatch:webhook:v${formatVersion}:${organizationId}:${endpointId}:${field}`;
  }
  return `zetuwatch:webhook:v${formatVersion}:key:${keyId}:${organizationId}:${endpointId}:${field}`;
}
