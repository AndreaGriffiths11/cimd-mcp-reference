import { describe, expect, it } from "vitest";
import { isIpLiteral, isLoopbackAddress, isPublicHostname, isSpecialUseAddress, parseIPv4, parseIPv6 } from "../src/auth/ssrf.js";

describe("IP parsing", () => {
  it("parses IPv4", () => {
    expect(parseIPv4("127.0.0.1")).toBe(0x7f000001);
    expect(parseIPv4("256.0.0.1")).toBeUndefined();
    expect(parseIPv4("1.2.3")).toBeUndefined();
  });
  it("parses IPv6 including compressed and IPv4-mapped forms", () => {
    expect(parseIPv6("::1")).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(parseIPv6("[2001:db8::1]")).toEqual([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
    expect(parseIPv6("::ffff:192.168.0.1")).toEqual([0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0001]);
    expect(parseIPv6("1::2::3")).toBeUndefined();
    expect(parseIPv6("gggg::1")).toBeUndefined();
  });
});

describe("RFC 6890 special-use detection", () => {
  it.each([
    "0.0.0.0",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "127.255.255.254",
    "169.254.169.254",
    "172.16.0.1",
    "172.31.255.255",
    "192.0.0.1",
    "192.0.2.1",
    "192.88.99.1",
    "192.168.1.1",
    "198.18.0.1",
    "198.51.100.1",
    "203.0.113.1",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
    "::",
    "::1",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "64:ff9b::1",
    "100::1",
    "2001:db8::1",
    "2001::1",
    "2002::1",
    "fc00::1",
    "fd12:3456::1",
    "fe80::1",
    "ff02::1",
  ])("flags %s", (address) => {
    expect(isSpecialUseAddress(address)).toBe(true);
  });

  it.each(["1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1", "172.15.255.255", "2606:4700:4700::1111", "2a00:1450:4001:80b::200e"])(
    "allows public address %s",
    (address) => {
      expect(isSpecialUseAddress(address)).toBe(false);
    },
  );

  it("treats unparseable input as special-use (fail closed)", () => {
    expect(isSpecialUseAddress("not-an-ip")).toBe(true);
  });

  it("identifies loopback specifically", () => {
    expect(isLoopbackAddress("127.0.0.1")).toBe(true);
    expect(isLoopbackAddress("127.9.9.9")).toBe(true);
    expect(isLoopbackAddress("::1")).toBe(true);
    expect(isLoopbackAddress("::ffff:127.0.0.1")).toBe(true);
    expect(isLoopbackAddress("10.0.0.1")).toBe(false);
    expect(isLoopbackAddress("1.1.1.1")).toBe(false);
  });
});

describe("hostname policy", () => {
  it("detects IP literals", () => {
    expect(isIpLiteral("1.2.3.4")).toBe(true);
    expect(isIpLiteral("[::1]")).toBe(true);
    expect(isIpLiteral("example.com")).toBe(false);
  });
  it("accepts public names and refuses local-only names", () => {
    expect(isPublicHostname("app.example.com")).toBe(true);
    expect(isPublicHostname("app.example.com.")).toBe(true);
    expect(isPublicHostname("localhost")).toBe(false);
    expect(isPublicHostname("router")).toBe(false);
    expect(isPublicHostname("nas.local")).toBe(false);
    expect(isPublicHostname("db.internal")).toBe(false);
    expect(isPublicHostname("x.home.arpa")).toBe(false);
    expect(isPublicHostname("site.onion")).toBe(false);
  });
});
