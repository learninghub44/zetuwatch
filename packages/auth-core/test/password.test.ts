import { describe, expect, it } from "vitest";
import { hashPassword, verifyPassword } from "../src/password";

describe("password hashing", () => {
  it("stores a salted PBKDF2 hash and verifies only the correct password", async () => {
    const password = "a-long-unique-passphrase";
    const stored = await hashPassword(password);
    expect(stored).toMatch(/^pbkdf2_sha256\$310000\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
    expect(await verifyPassword(password, stored)).toBe(true);
    expect(await verifyPassword("a-different-passphrase", stored)).toBe(false);
  });

  it("rejects invalid password lengths", async () => {
    await expect(hashPassword("short")).rejects.toThrow("PASSWORD_LENGTH_INVALID");
    await expect(hashPassword("x".repeat(129))).rejects.toThrow("PASSWORD_LENGTH_INVALID");
  });

  it("rejects malformed or unsupported stored hashes", async () => {
    expect(await verifyPassword("valid-password-123", "not-a-hash")).toBe(false);
    expect(await verifyPassword("valid-password-123", "pbkdf2_sha256$1$AA$AA")).toBe(false);
  });

  it("rejects empty and oversized login passwords without deriving a hash", async () => {
    expect(await verifyPassword("", "not-a-hash")).toBe(false);
    expect(await verifyPassword("x".repeat(129), "not-a-hash")).toBe(false);
  });
});
