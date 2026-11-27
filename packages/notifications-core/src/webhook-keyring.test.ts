import { describe, expect, it } from "vitest";
import {
  getWebhookEncryptionKey,
  readWebhookKeyring,
  webhookEncryptionContext
} from "./webhook-keyring";

const KEY_V1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const KEY_V2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

describe("webhook encryption keyring", () => {
  it("preserves the legacy v1 key id for existing installations", () => {
    const keyring = readWebhookKeyring({ WEBHOOK_ENCRYPTION_KEY: KEY_V1 });
    expect(keyring.current).toEqual({ id: "v1", value: KEY_V1 });
    expect(keyring.previous).toBeUndefined();
    expect(getWebhookEncryptionKey(keyring, "v1")).toEqual({ id: "v1", value: KEY_V1 });
  });

  it("supports a current key and one decrypt-only previous key", () => {
    const keyring = readWebhookKeyring({
      WEBHOOK_ENCRYPTION_KEY: KEY_V2,
      WEBHOOK_ENCRYPTION_KEY_ID: "v2",
      WEBHOOK_ENCRYPTION_KEY_PREVIOUS: KEY_V1,
      WEBHOOK_ENCRYPTION_KEY_PREVIOUS_ID: "v1"
    });
    expect(keyring.current).toEqual({ id: "v2", value: KEY_V2 });
    expect(keyring.previous).toEqual({ id: "v1", value: KEY_V1 });
    expect(getWebhookEncryptionKey(keyring, "v1")).toEqual({ id: "v1", value: KEY_V1 });
    expect(getWebhookEncryptionKey(keyring, "v2")).toEqual({ id: "v2", value: KEY_V2 });
  });

  it("defaults the previous key id to the legacy id during the first rotation", () => {
    const keyring = readWebhookKeyring({
      WEBHOOK_ENCRYPTION_KEY: KEY_V2,
      WEBHOOK_ENCRYPTION_KEY_ID: "v2",
      WEBHOOK_ENCRYPTION_KEY_PREVIOUS: KEY_V1
    });
    expect(keyring.previous?.id).toBe("v1");
  });

  it("rejects missing, malformed, ambiguous and duplicate key configuration", () => {
    expect(() => readWebhookKeyring({})).toThrow("WEBHOOK_ENCRYPTION_KEY_MISSING");
    expect(() => readWebhookKeyring({ WEBHOOK_ENCRYPTION_KEY: "bad" }))
      .toThrow("WEBHOOK_ENCRYPTION_KEY_INVALID");
    expect(() => readWebhookKeyring({
      WEBHOOK_ENCRYPTION_KEY: KEY_V1,
      WEBHOOK_ENCRYPTION_KEY_ID: "../v2"
    })).toThrow("WEBHOOK_ENCRYPTION_KEY_ID_INVALID");
    expect(() => readWebhookKeyring({
      WEBHOOK_ENCRYPTION_KEY: KEY_V2,
      WEBHOOK_ENCRYPTION_KEY_ID: "v2",
      WEBHOOK_ENCRYPTION_KEY_PREVIOUS: KEY_V1,
      WEBHOOK_ENCRYPTION_KEY_PREVIOUS_ID: "v2"
    })).toThrow("WEBHOOK_ENCRYPTION_KEY_IDS_MUST_DIFFER");
    expect(() => readWebhookKeyring({
      WEBHOOK_ENCRYPTION_KEY: KEY_V2,
      WEBHOOK_ENCRYPTION_KEY_ID: "v2",
      WEBHOOK_ENCRYPTION_KEY_PREVIOUS_ID: "v1"
    })).toThrow("WEBHOOK_PREVIOUS_KEY_ID_WITHOUT_KEY");
  });

  it("does not silently fall back when a stored key id is unavailable", () => {
    const keyring = readWebhookKeyring({ WEBHOOK_ENCRYPTION_KEY: KEY_V2, WEBHOOK_ENCRYPTION_KEY_ID: "v2" });
    expect(() => getWebhookEncryptionKey(keyring, "v1")).toThrow("WEBHOOK_ENCRYPTION_KEY_ID_UNAVAILABLE");
  });

  it("keeps legacy AAD byte-for-byte and binds later key ids into AAD", () => {
    expect(webhookEncryptionContext(1, "v1", "org", "endpoint", "url"))
      .toBe("zetuwatch:webhook:v1:org:endpoint:url");
    expect(webhookEncryptionContext(1, "v2", "org", "endpoint", "url"))
      .toBe("zetuwatch:webhook:v1:key:v2:org:endpoint:url");
    expect(webhookEncryptionContext(1, "v2", "org", "endpoint", "secret"))
      .not.toBe(webhookEncryptionContext(1, "v3", "org", "endpoint", "secret"));
  });
});
