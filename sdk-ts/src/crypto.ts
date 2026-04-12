/**
 * End-to-end encryption and message signing for inter-agent messages.
 *
 * Encryption: AES-256-GCM (data)
 *   + RSA-OAEP-SHA256 (key wrapping, RSA recipients)
 *   + ECDH ephemeral + HKDF-SHA256 (key wrapping, EC recipients)
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
  createPublicKey,
  createPrivateKey,
  generateKeyPairSync,
  diffieHellman,
  hkdfSync,
  constants,
  type KeyObject,
} from "node:crypto";
import type { CipherBlob } from "./types.js";
import { base64url, base64urlDecode, canonicalJson } from "./utils.js";

const HKDF_INFO = Buffer.from("cullis-e2e-v1", "utf-8");
const HKDF_SALT = Buffer.alloc(0);

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

// ── E2E Encryption (AES-256-GCM + RSA-OAEP or ECDH+HKDF) ────────

function xorBuffers(a: Buffer, b: Buffer): Buffer {
  if (a.length !== b.length) {
    throw new Error("xor length mismatch");
  }
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) {
    out[i] = a[i]! ^ b[i]!;
  }
  return out;
}

function wrapAesKeyRsa(
  recipientPubKey: KeyObject,
  aesKey: Buffer,
): { encrypted_key: string } {
  const encryptedKey = publicEncrypt(
    {
      key: recipientPubKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    aesKey,
  );
  return { encrypted_key: base64url(encryptedKey) };
}

function wrapAesKeyEc(
  recipientPubKey: KeyObject,
  aesKey: Buffer,
): { encrypted_key: string; ephemeral_pubkey: string } {
  const details = recipientPubKey.asymmetricKeyDetails;
  const namedCurve = details?.namedCurve;
  if (!namedCurve) {
    throw new Error("EC recipient key missing namedCurve");
  }
  const ephemeral = generateKeyPairSync("ec", { namedCurve });
  const sharedSecret = diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: recipientPubKey,
  });
  const derived = Buffer.from(
    hkdfSync("sha256", sharedSecret, HKDF_SALT, HKDF_INFO, 32),
  );
  const encryptedKey = xorBuffers(aesKey, derived);
  const ephemeralPubPem = ephemeral.publicKey
    .export({ type: "spki", format: "pem" })
    .toString();
  return {
    encrypted_key: base64url(encryptedKey),
    ephemeral_pubkey: base64url(Buffer.from(ephemeralPubPem, "utf-8")),
  };
}

function unwrapAesKeyRsa(
  recipientPrivKey: KeyObject,
  blob: CipherBlob,
): Buffer {
  const encryptedKey = base64urlDecode(blob.encrypted_key);
  return privateDecrypt(
    {
      key: recipientPrivKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
    },
    encryptedKey,
  );
}

function unwrapAesKeyEc(
  recipientPrivKey: KeyObject,
  blob: CipherBlob,
): Buffer {
  if (!blob.ephemeral_pubkey) {
    throw new Error("EC recipient requires ephemeral_pubkey in cipher blob");
  }
  const ephemeralPubPem = base64urlDecode(blob.ephemeral_pubkey).toString(
    "utf-8",
  );
  const ephemeralPub = createPublicKey(ephemeralPubPem);
  const sharedSecret = diffieHellman({
    privateKey: recipientPrivKey,
    publicKey: ephemeralPub,
  });
  const derived = Buffer.from(
    hkdfSync("sha256", sharedSecret, HKDF_SALT, HKDF_INFO, 32),
  );
  const encryptedKey = base64urlDecode(blob.encrypted_key);
  return xorBuffers(encryptedKey, derived);
}


/**
 * Encrypt a payload for a specific recipient agent.
 *
 * Schema: AES-256-GCM encrypts {payload, inner_signature} as JSON.
 * The AES key is wrapped with the recipient's public key:
 *   - RSA keys: RSA-OAEP-SHA256
 *   - EC keys:  ephemeral ECDH + HKDF-SHA256 (info="cullis-e2e-v1"), XOR wrap
 * AAD binds the ciphertext to the session context.
 */
export function encryptForAgent(
  payload: Record<string, unknown>,
  recipientPublicKeyPem: string,
  sessionId: string,
  senderAgentId: string,
  innerSignature: string,
  clientSeq?: number | null,
): CipherBlob {
  const innerEnvelope = canonicalJson({
    inner_signature: innerSignature,
    payload,
  });
  const plaintext = Buffer.from(innerEnvelope, "utf-8");

  const aesKey = randomBytes(32);
  const iv = randomBytes(12);

  let aad: Buffer;
  if (clientSeq !== undefined && clientSeq !== null) {
    aad = Buffer.from(`${sessionId}|${senderAgentId}|${clientSeq}`, "utf-8");
  } else {
    aad = Buffer.from(`${sessionId}|${senderAgentId}`, "utf-8");
  }

  const cipher = createCipheriv("aes-256-gcm", aesKey, iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  const ciphertextWithTag = Buffer.concat([encrypted, authTag]);

  const recipientPubKey = createPublicKey(recipientPublicKeyPem);
  let keyWrap: { encrypted_key: string; ephemeral_pubkey?: string };
  if (recipientPubKey.asymmetricKeyType === "rsa") {
    keyWrap = wrapAesKeyRsa(recipientPubKey, aesKey);
  } else if (recipientPubKey.asymmetricKeyType === "ec") {
    keyWrap = wrapAesKeyEc(recipientPubKey, aesKey);
  } else {
    throw new Error(
      `Unsupported recipient key type: ${recipientPubKey.asymmetricKeyType}`,
    );
  }

  return {
    ciphertext: base64url(ciphertextWithTag),
    iv: base64url(iv),
    ...keyWrap,
  };
}

/**
 * Decrypt an E2E encrypted message.
 * Supports both RSA-OAEP and ECDH+HKDF key unwrapping.
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
  const recipientPrivKey = createPrivateKey(privateKeyPem);
  let aesKey: Buffer;
  if (recipientPrivKey.asymmetricKeyType === "rsa") {
    aesKey = unwrapAesKeyRsa(recipientPrivKey, encryptedMessage);
  } else if (recipientPrivKey.asymmetricKeyType === "ec") {
    aesKey = unwrapAesKeyEc(recipientPrivKey, encryptedMessage);
  } else {
    throw new Error(
      `Unsupported recipient key type: ${recipientPrivKey.asymmetricKeyType}`,
    );
  }

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
