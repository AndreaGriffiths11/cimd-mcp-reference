/**
 * PKCE (RFC 7636) with the S256 method only. OAuth 2.1 requires PKCE for every
 * authorization code flow and MCP clients MUST use S256, so `plain` is refused.
 */

import { sha256Base64url, timingSafeEqual } from "../http.js";

const CODE_CHALLENGE_PATTERN = /^[A-Za-z0-9\-_]{43}$/;
const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;

export type PkceCheck = { ok: true } | { ok: false; error: string };

/** Validates the authorization request parameters. */
export function validateCodeChallenge(codeChallenge: string | null, method: string | null): PkceCheck {
  if (!codeChallenge) return { ok: false, error: "code_challenge is required (PKCE)" };
  if (method !== "S256") return { ok: false, error: "code_challenge_method must be S256" };
  if (!CODE_CHALLENGE_PATTERN.test(codeChallenge)) {
    return { ok: false, error: "code_challenge must be 43 base64url characters (SHA-256 of the verifier)" };
  }
  return { ok: true };
}

/** Validates the token request's verifier against the stored challenge. */
export async function verifyCodeVerifier(codeVerifier: string | null, storedChallenge: string): Promise<PkceCheck> {
  if (!codeVerifier) return { ok: false, error: "code_verifier is required" };
  if (!CODE_VERIFIER_PATTERN.test(codeVerifier)) {
    return { ok: false, error: "code_verifier must be 43 to 128 unreserved characters" };
  }
  const computed = await sha256Base64url(codeVerifier);
  if (!timingSafeEqual(computed, storedChallenge)) return { ok: false, error: "code_verifier does not match code_challenge" };
  return { ok: true };
}

/** Helper for clients and tests: derives the S256 challenge for a verifier. */
export async function computeCodeChallenge(codeVerifier: string): Promise<string> {
  return sha256Base64url(codeVerifier);
}
