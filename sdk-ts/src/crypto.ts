/**
 * End-to-end encryption and message signing for inter-agent messages.
 *
 * Encryption: AES-256-GCM (data) + RSA-OAEP-SHA256 (key wrapping)
 * Signing:    RSA-PSS-SHA256
 *
 * This mirrors app/e2e_crypto.py and app/auth/message_signer.py exactly,
 * so that a TypeScript agent can interoperate with Python agents.
 */
import {
  createSign,
  createVerify,
  publicEncrypt,
  privateDecrypt,
  randomBytes,
  createCipheriv,
  createDecipheriv,
  constants,
} from "node:crypto";
import type { CipherBlob } from "./types.js";
import { base64url, base64urlDecode, canonicalJson } from "./utils.js";

// ── Message Signing (RSA-PSS-SHA256) ──────────────────────────────

/**
 * Build the canonical byte string that gets signed.
 * Must match Python's _canonical() in app/auth/message_signer.py.
 */
function buildCanonical(
  sessionId: string,
  senderAgentId: string,
  nonce: string,
  timestamp: number,
  payload: Record<string, unknown>,
  clientSeq?: number | null,
): Buffer {
  const payloadStr = canonicalJson(payload);
  let canonical: string;
  if (clientSeq !== undefined && clientSeq !== null) {
    canonical = `${sessionId}|${senderAgentId}|${nonce}|${timestamp}|${clientSeq}|${payloadStr}`;
  } else {
    canonical = `${sessionId}|${senderAgentId}|${nonce}|${timestamp}|${payloadStr}`;
  }
  return Buffer.from(canonical, "utf-8");
}

/**
 * Sign a message with the agent's RSA private key using RSA-PSS-SHA256.
 * Returns the signature as a URL-safe base64 string (no padding).
 */
export function signMessage(
  privateKeyPem: string,
  sessionId: string,
  senderAgentId: string,
  nonce: string,
  timestamp: number,
  payload: Record<string, unknown>,
  clientSeq?: number | null,
): string {
  const canonical = buildCanonical(
    sessionId,
    senderAgentId,
    nonce,
    timestamp,
    payload,
    clientSeq,
  );

  const signer = createSign("SHA256");
  signer.update(canonical);
  const signature = signer.sign({
    key: privateKeyPem,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: constants.RSA_PSS_SALTLEN_MAX_SIGN,
  });

  return base64url(signature);
}

/**
 * Verify an RSA-PSS-SHA256 message signature.
 * Returns true if valid, throws Error if invalid.
 */
export function verifyMessageSignature(
  publicKeyPem: string,
  signatureB64: string,
  sessionId: string,
  senderAgentId: string,
  nonce: string,
  timestamp: number,
  payload: Record<string, unknown>,
  clientSeq?: number | null,
): boolean {
  const canonical = buildCanonical(
    sessionId,
    senderAgentId,
    nonce,
    timestamp,
    payload,
    clientSeq,
  );
  const sig = base64urlDecode(signatureB64);

  const verifier = createVerify("SHA256");
  verifier.update(canonical);
  const valid = verifier.verify(
    {
      key: publicKeyPem,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: constants.RSA_PSS_SALTLEN_MAX_SIGN,
    },
    sig,
  );

  if (!valid) {
    throw new Error("Message signature verification failed");
  }
  return true;
}

// ── E2E Encryption (AES-256-GCM + RSA-OAEP) ─────────────────────

/**
 * Encrypt a payload for a specific recipient agent.
 *
 * Schema: AES-256-GCM encrypts {payload, inner_signature} as JSON.
 * The AES key is wrapped with the recipient's RSA public key (OAEP-SHA256).
 * AAD binds the ciphertext to the session context.
 *
 * Returns: { ciphertext, encrypted_key, iv } all base64url-encoded.
 */
export function encryptForAgent(
  payload: Record<string, unknown>,
  recipientPublicKeyPem: string,
  sessionId: string,
  senderAgentId: string,
  innerSignature: string,
  clientSeq?: number | null,
): CipherBlob {
  // Serialize the inner envelope (payload + signature) as canonical JSON
  const innerEnvelope = canonicalJson({
    inner_signature: innerSignature,
    payload,
  });
  const plaintext = Buffer.from(innerEnvelope, "utf-8");

  // Generate random AES-256 key and 12-byte IV
  const aesKey = randomBytes(32);
  const iv = randomBytes(12);

  // Build AAD to bind ciphertext to session context
  let aad: Buffer;
  if (clientSeq !== undefined && clientSeq !== null) {
    aad = Buffer.from(`${sessionId}|${senderAgentId}|${clientSeq}`, "utf-8");
  } else {
    aad = Buffer.from(`${sessionId}|${senderAgentId}`, "utf-8");
  }

  // AES-256-GCM encrypt
  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag(); // 16 bytes
  // Python appends the tag to ciphertext
  const ciphertextWithTag = Buffer.concat([encrypted, authTag]);

  // RSA-OAEP-SHA256 wrap the AES key
  const encryptedKey = publicEncrypt(
    {
      key: recipientPublicKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey,
  );

  return {
    ciphertext: base64url(ciphertextWithTag),
    encrypted_key: base64url(encryptedKey),
    iv: base64url(iv),
  };
}

/**
 * Decrypt an E2E encrypted message.
 *
 * @returns [plaintextPayload, innerSignature]
 */
export function decryptFromAgent(
  encryptedMessage: CipherBlob,
  privateKeyPem: string,
  sessionId: string,
  senderAgentId: string,
  clientSeq?: number | null,
): [Record<string, unknown>, string] {
  // Unwrap AES key with RSA-OAEP-SHA256
  const encryptedKey = base64urlDecode(encryptedMessage.encrypted_key);
  const aesKey = privateDecrypt(
    {
      key: privateKeyPem,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    encryptedKey,
  );

  const ivBuf = base64urlDecode(encryptedMessage.iv);
  const ciphertextWithTag = base64urlDecode(encryptedMessage.ciphertext);

  // Split: ciphertext is everything except last 16 bytes (GCM tag)
  const tagStart = ciphertextWithTag.length - 16;
  const ciphertext = ciphertextWithTag.subarray(0, tagStart);
  const authTag = ciphertextWithTag.subarray(tagStart);

  // Build AAD
  let aad: Buffer;
  if (clientSeq !== undefined && clientSeq !== null) {
    aad = Buffer.from(`${sessionId}|${senderAgentId}|${clientSeq}`, "utf-8");
  } else {
    aad = Buffer.from(`${sessionId}|${senderAgentId}`, "utf-8");
  }

  // AES-256-GCM decrypt
  const decipher = createDecipheriv("aes-256-gcm", aesKey, ivBuf);
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  const data = JSON.parse(plaintext.toString("utf-8")) as {
    payload: Record<string, unknown>;
    inner_signature: string;
  };

  return [data.payload, data.inner_signature];
}
