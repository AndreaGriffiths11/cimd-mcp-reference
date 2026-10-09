import { describe, expect, it } from "vitest";
import { computeCodeChallenge, validateCodeChallenge, verifyCodeVerifier } from "../src/auth/pkce.js";

describe("PKCE S256", () => {
  // RFC 7636 appendix B test vector.
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

  it("derives the challenge from the verifier", async () => {
    expect(await computeCodeChallenge(verifier)).toBe(challenge);
  });

  it("accepts only S256 with a well-formed challenge on the authorization request", () => {
    expect(validateCodeChallenge(challenge, "S256")).toEqual({ ok: true });
    expect(validateCodeChallenge(null, "S256").ok).toBe(false);
    expect(validateCodeChallenge(challenge, "plain").ok).toBe(false);
    expect(validateCodeChallenge(challenge, null).ok).toBe(false);
    expect(validateCodeChallenge("short", "S256").ok).toBe(false);
    expect(validateCodeChallenge(`${challenge}=`, "S256").ok).toBe(false);
  });

  it("verifies the verifier against the stored challenge at the token endpoint", async () => {
    expect(await verifyCodeVerifier(verifier, challenge)).toEqual({ ok: true });
    expect((await verifyCodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXX", challenge)).ok).toBe(false);
    expect((await verifyCodeVerifier(null, challenge)).ok).toBe(false);
  });

  it("rejects verifiers outside the RFC 7636 grammar", async () => {
    expect((await verifyCodeVerifier("too-short", challenge)).ok).toBe(false);
    expect((await verifyCodeVerifier("a".repeat(129), challenge)).ok).toBe(false);
    expect((await verifyCodeVerifier(`${"a".repeat(42)}!`, challenge)).ok).toBe(false);
  });
});
