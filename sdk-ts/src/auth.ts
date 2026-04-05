/**
 * Authentication helpers: x509 client_assertion JWT + DPoP proof generation.
 *
 * Uses the `jose` library for JWT operations and Node.js crypto for
 * key/certificate manipulation.
 */
import { createHash, generateKeyPairSync, KeyObject } from "node:crypto";
import { X509Certificate } from "node:crypto";
import { SignJWT, importPKCS8, exportJWK } from "jose";
import type { JWK } from "jose";
import { base64url } from "./utils.js";

// ── Client Assertion (x509 + RS256) ──────────────────────────────

/**
 * Create a JWT client_assertion signed with the agent's RSA private key.
 * The x5c header contains the DER-encoded certificate (base64 standard).
 *
 * This mirrors the Python SDK's login() assertion creation.
 */
export async function createClientAssertion(
  agentId: string,
  _orgId: string,
  certPem: string,
  keyPem: string,
): Promise<string> {
  // Extract DER from the PEM certificate for x5c header
  const cert = new X509Certificate(certPem);
  const certDer = cert.raw;
  const x5c = [Buffer.from(certDer).toString("base64")];

  // Import the RSA private key for signing
  const privateKey = await importPKCS8(keyPem, "RS256");

  const now = Math.floor(Date.now() / 1000);
  const jti = crypto.randomUUID();

  return new SignJWT({
    sub: agentId,
    iss: agentId,
    aud: "agent-trust-broker",
    iat: now,
    exp: now + 300, // 5 minutes
    jti,
  })
    .setProtectedHeader({ alg: "RS256", x5c })
    .sign(privateKey);
}

// ── DPoP (RFC 9449) ──────────────────────────────────────────────

/** An ephemeral EC P-256 key pair for DPoP proofs. */
export interface DPoPKeyPair {
  privateKey: KeyObject;
  publicJwk: JWK;
}

/**
 * Generate an ephemeral EC P-256 key pair for DPoP proofs.
 * The public key is exported as a JWK for inclusion in DPoP proof headers.
 */
export async function generateDPoPKeyPair(): Promise<DPoPKeyPair> {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });

  // Export public key as JWK — jose needs a CryptoKey-like or KeyObject
  const pubJwk = await exportJWK(publicKey);
  // Only include kty, crv, x, y (no private components)
  const publicJwk: JWK = {
    kty: pubJwk.kty,
    crv: pubJwk.crv,
    x: pubJwk.x,
    y: pubJwk.y,
  };

  return { privateKey, publicJwk };
}

/**
 * Options for creating a DPoP proof.
 */
export interface DPoPProofOptions {
  /** Access token to bind via ath claim */
  accessToken?: string;
  /** Server-provided nonce (RFC 9449 section 8) */
  nonce?: string;
}

/**
 * Create a DPoP proof JWT (RFC 9449).
 *
 * @param method - HTTP method (GET, POST, etc.)
 * @param url    - Full URL of the request
 * @param privateKey - EC P-256 private key
 * @param publicJwk  - Corresponding public JWK for the header
 * @param options    - Optional access token and nonce
 */
export async function createDPoPProof(
  method: string,
  url: string,
  privateKey: KeyObject,
  publicJwk: JWK,
  options?: DPoPProofOptions,
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const claims: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm: method.toUpperCase(),
    htu: url,
    iat: now,
  };

  if (options?.accessToken) {
    // ath = base64url(SHA-256(access_token))
    const hash = createHash("sha256")
      .update(options.accessToken, "utf-8")
      .digest();
    claims.ath = base64url(hash);
  }

  if (options?.nonce) {
    claims.nonce = options.nonce;
  }

  return new SignJWT(claims as Record<string, string | number>)
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: publicJwk })
    .sign(privateKey);
}

/**
 * Compute the JWK Thumbprint (RFC 7638) of a JWK using SHA-256.
 * Returns the thumbprint as a base64url string.
 */
export function computeJwkThumbprint(jwk: JWK): string {
  // Per RFC 7638 the members depend on the key type
  let members: Record<string, string | undefined>;
  if (jwk.kty === "EC") {
    members = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  } else if (jwk.kty === "RSA") {
    members = { e: jwk.e, kty: jwk.kty, n: jwk.n };
  } else {
    throw new Error(`Unsupported key type for thumbprint: ${jwk.kty}`);
  }

  // Lexicographic order of keys, compact JSON
  const sortedKeys = Object.keys(members).sort();
  const canonical: Record<string, string> = {};
  for (const k of sortedKeys) {
    const v = members[k];
    if (v !== undefined) {
      canonical[k] = v;
    }
  }
  const json = JSON.stringify(canonical);
  const hash = createHash("sha256").update(json, "utf-8").digest();
  return base64url(hash);
}
