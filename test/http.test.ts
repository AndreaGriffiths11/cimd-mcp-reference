import { describe, expect, it } from "vitest";
import { FormError, MAX_FORM_BYTES, readForm } from "../src/http.js";

const FORM = "application/x-www-form-urlencoded";

function streamOf(text: string, chunkSize = 1024): ReadableStream<Uint8Array> {
  const bytes = new TextEncoder().encode(text);
  let offset = 0;
  return new ReadableStream({
    pull(controller) {
      if (offset >= bytes.length) {
        controller.close();
        return;
      }
      controller.enqueue(bytes.slice(offset, offset + chunkSize));
      offset += chunkSize;
    },
  });
}

async function formError(promise: Promise<unknown>): Promise<FormError> {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(FormError);
  return error as FormError;
}

describe("readForm", () => {
  it("parses a form under the limit", async () => {
    const request = new Request("https://as.example/token", {
      method: "POST",
      headers: { "Content-Type": FORM },
      body: "grant_type=authorization_code&code=abc",
    });
    const form = await readForm(request);
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("code")).toBe("abc");
  });

  it("accepts a body of exactly the limit", async () => {
    const body = `a=${"x".repeat(MAX_FORM_BYTES - 2)}`;
    const request = new Request("https://as.example/token", {
      method: "POST",
      headers: { "Content-Type": FORM, "Content-Length": String(body.length) },
      body,
    });
    expect((await readForm(request)).get("a")).toHaveLength(MAX_FORM_BYTES - 2);
  });

  it("refuses an over-limit Content-Length before reading the body", async () => {
    const body = `a=${"x".repeat(MAX_FORM_BYTES)}`;
    const request = new Request("https://as.example/token", {
      method: "POST",
      headers: { "Content-Type": FORM, "Content-Length": String(body.length) },
      body,
    });
    const error = await formError(readForm(request));
    expect(error.status).toBe(413);
    expect(error.message).toContain(`${MAX_FORM_BYTES} bytes`);
    expect(request.bodyUsed).toBe(false);
  });

  it("stops reading an over-limit body that has no Content-Length", async () => {
    const request = new Request("https://as.example/token", {
      method: "POST",
      headers: { "Content-Type": FORM },
      body: streamOf(`a=${"x".repeat(MAX_FORM_BYTES * 4)}`),
      // @ts-expect-error duplex is required for stream bodies but missing from the RequestInit type
      duplex: "half",
    });
    expect(request.headers.get("Content-Length")).toBeNull();
    const error = await formError(readForm(request));
    expect(error.status).toBe(413);
  });

  it("enforces the limit when Content-Length understates the body", async () => {
    const request = new Request("https://as.example/token", {
      method: "POST",
      headers: { "Content-Type": FORM, "Content-Length": "10" },
      body: streamOf(`a=${"x".repeat(MAX_FORM_BYTES * 2)}`),
      // @ts-expect-error duplex is required for stream bodies but missing from the RequestInit type
      duplex: "half",
    });
    const error = await formError(readForm(request));
    expect(error.status).toBe(413);
  });

  it("rejects a non-form Content-Type with 400", async () => {
    const request = new Request("https://as.example/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const error = await formError(readForm(request));
    expect(error.status).toBe(400);
  });
});
