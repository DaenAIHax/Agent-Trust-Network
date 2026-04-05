/**
 * Utility functions: canonical JSON, base64url, hashing.
 *
 * The canonical JSON format MUST match the Python implementation:
 *   json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
 */
import { createHash } from "node:crypto";

/**
 * Produce canonical JSON: sorted keys, no spaces, ASCII-safe.
 *
 * This mirrors Python's json.dumps(obj, sort_keys=True, separators=(",", ":")).
 * Objects are recursively sorted by key; arrays preserve order.
 */
export function canonicalJson(obj: unknown): string {
  return JSON.stringify(sortKeys(obj));
}

/**
 * Recursively sort object keys so that JSON.stringify produces
 * deterministic output equivalent to Python's sort_keys=True.
 */
function sortKeys(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = sortKeys((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * Encode a Buffer/Uint8Array to URL-safe base64 (no padding).
 */
export function base64url(buf: Buffer | Uint8Array): string {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Decode a URL-safe base64 string (with or without padding) to Buffer.
 */
export function base64urlDecode(str: string): Buffer {
  // Re-add padding if needed
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad === 2) s += "==";
  else if (pad === 3) s += "=";
  return Buffer.from(s, "base64");
}

/**
 * Compute SHA-256 hash of the canonical JSON representation of an object.
 * Returns the hash as a hex string.
 */
export function computePayloadHash(payload: Record<string, unknown>): string {
  const canonical = canonicalJson(payload);
  return createHash("sha256").update(canonical, "utf-8").digest("hex");
}
