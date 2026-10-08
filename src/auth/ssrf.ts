/**
 * Server-Side Request Forgery guards for fetching Client ID Metadata Documents.
 *
 * draft-ietf-oauth-client-id-metadata-document section 6.5: the authorization
 * server MUST validate that the client_id URL does not resolve to a
 * special-use IP address (RFC 6890), except when the server itself runs on
 * loopback and the address matches that interface.
 *
 * Two layers are applied before any fetch:
 *   1. The hostname itself: IP literals are checked against the RFC 6890
 *      ranges, and names that can only be local (`localhost`, `*.local`,
 *      `*.internal`, single-label names) are refused.
 *   2. DNS: the name is resolved with DNS over HTTPS and every A/AAAA answer
 *      is checked against the same ranges.
 *
 * Residual risk: a Worker cannot pin the IP a later fetch() connects to, so a
 * DNS rebinding attacker could pass step 2 and then answer differently. On
 * Cloudflare this is contained because Workers cannot open connections to
 * private or loopback addresses at all. Self-hosters on other runtimes should
 * add network policy.
 */

export type ResolveAddresses = (hostname: string) => Promise<string[]>;

interface Cidr4 {
  base: number;
  bits: number;
}

const SPECIAL_V4: Cidr4[] = [
  cidr4("0.0.0.0", 8), // "this" network
  cidr4("10.0.0.0", 8), // private
  cidr4("100.64.0.0", 10), // shared address space (CGNAT)
  cidr4("127.0.0.0", 8), // loopback
  cidr4("169.254.0.0", 16), // link local (includes cloud metadata 169.254.169.254)
  cidr4("172.16.0.0", 12), // private
  cidr4("192.0.0.0", 24), // IETF protocol assignments
  cidr4("192.0.2.0", 24), // TEST-NET-1
  cidr4("192.88.99.0", 24), // 6to4 relay anycast (deprecated)
  cidr4("192.168.0.0", 16), // private
  cidr4("198.18.0.0", 15), // benchmarking
  cidr4("198.51.100.0", 24), // TEST-NET-2
  cidr4("203.0.113.0", 24), // TEST-NET-3
  cidr4("224.0.0.0", 4), // multicast
  cidr4("240.0.0.0", 4), // reserved, includes 255.255.255.255
];

function cidr4(ip: string, bits: number): Cidr4 {
  return { base: parseIPv4(ip)!, bits };
}

export function parseIPv4(text: string): number | undefined {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!m) return undefined;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const octet = Number(m[i]);
    if (octet > 255) return undefined;
    n = (n << 8) | octet;
  }
  return n >>> 0;
}

function inCidr4(ip: number, cidr: Cidr4): boolean {
  if (cidr.bits === 0) return true;
  const mask = (0xffffffff << (32 - cidr.bits)) >>> 0;
  return ((ip & mask) >>> 0) === ((cidr.base & mask) >>> 0);
}

/** Expands an IPv6 literal (without brackets) into eight 16-bit groups, or undefined if malformed. */
export function parseIPv6(text: string): number[] | undefined {
  let s = text;
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  const zone = s.indexOf("%");
  if (zone !== -1) s = s.slice(0, zone);
  if (!/^[0-9a-fA-F:.]+$/.test(s)) return undefined;

  // Embedded IPv4 tail, for example ::ffff:127.0.0.1
  const lastColon = s.lastIndexOf(":");
  if (s.includes(".")) {
    const v4 = parseIPv4(s.slice(lastColon + 1));
    if (v4 === undefined) return undefined;
    s = `${s.slice(0, lastColon)}:${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }

  const parts = s.split("::");
  if (parts.length > 2) return undefined;
  const head = parts[0] ? parts[0].split(":") : [];
  const tail = parts.length === 2 && parts[1] ? parts[1].split(":") : [];
  if (parts.length === 1 && head.length !== 8) return undefined;
  if (parts.length === 2 && head.length + tail.length > 7) return undefined;
  const groups = [...head, ...Array<string>(8 - head.length - tail.length).fill("0"), ...tail];
  const out: number[] = [];
  for (const g of groups) {
    if (g.length === 0 || g.length > 4) return undefined;
    out.push(parseInt(g, 16));
  }
  return out;
}

function v6Prefix(groups: number[], bits: number, prefix: number[]): boolean {
  let remaining = bits;
  for (let i = 0; i < 8 && remaining > 0; i++) {
    const take = Math.min(16, remaining);
    const mask = (0xffff << (16 - take)) & 0xffff;
    if ((groups[i]! & mask) !== ((prefix[i] ?? 0) & mask)) return false;
    remaining -= take;
  }
  return true;
}

const SPECIAL_V6: Array<{ prefix: number[]; bits: number }> = [
  { prefix: parseIPv6("::")!, bits: 128 }, // unspecified
  { prefix: parseIPv6("::1")!, bits: 128 }, // loopback
  { prefix: parseIPv6("::ffff:0:0")!, bits: 96 }, // IPv4-mapped, checked separately as IPv4 too
  { prefix: parseIPv6("64:ff9b::")!, bits: 96 }, // IPv4/IPv6 translation
  { prefix: parseIPv6("64:ff9b:1::")!, bits: 48 }, // local-use translation
  { prefix: parseIPv6("100::")!, bits: 64 }, // discard-only
  { prefix: parseIPv6("2001::")!, bits: 23 }, // IETF protocol assignments (TEREDO, ORCHID, benchmarking, documentation)
  { prefix: parseIPv6("2002::")!, bits: 16 }, // 6to4
  { prefix: parseIPv6("fc00::")!, bits: 7 }, // unique local
  { prefix: parseIPv6("fe80::")!, bits: 10 }, // link local
  { prefix: parseIPv6("ff00::")!, bits: 8 }, // multicast
];

/** True when the address is in an RFC 6890 special-purpose range (private, loopback, link-local, etc.). */
export function isSpecialUseAddress(address: string): boolean {
  const v4 = parseIPv4(address);
  if (v4 !== undefined) return SPECIAL_V4.some((c) => inCidr4(v4, c));
  const v6 = parseIPv6(address);
  if (!v6) return true; // unparseable: fail closed
  if (v6Prefix(v6, 96, SPECIAL_V6[2]!.prefix)) {
    const mapped = ((v6[6]! << 16) | v6[7]!) >>> 0;
    return SPECIAL_V4.some((c) => inCidr4(mapped, c));
  }
  return SPECIAL_V6.some((r) => v6Prefix(v6, r.bits, r.prefix));
}

export function isLoopbackAddress(address: string): boolean {
  const v4 = parseIPv4(address);
  if (v4 !== undefined) return inCidr4(v4, SPECIAL_V4[3]!);
  const v6 = parseIPv6(address);
  if (!v6) return false;
  if (v6Prefix(v6, 96, SPECIAL_V6[2]!.prefix)) return inCidr4(((v6[6]! << 16) | v6[7]!) >>> 0, SPECIAL_V4[3]!);
  return v6Prefix(v6, 128, SPECIAL_V6[1]!.prefix);
}

export function isIpLiteral(hostname: string): boolean {
  return parseIPv4(hostname) !== undefined || parseIPv6(hostname) !== undefined;
}

const LOCAL_ONLY_SUFFIXES = [".localhost", ".local", ".internal", ".localdomain", ".home.arpa", ".onion", ".test", ".example", ".invalid"];

/**
 * Rejects hostnames that cannot name a public server: loopback names, mDNS
 * and intranet suffixes, and single-label names (which resolve via search
 * domains inside corporate networks).
 */
export function isPublicHostname(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  if (h === "localhost") return false;
  if (!h.includes(".")) return false;
  if (LOCAL_ONLY_SUFFIXES.some((suffix) => h.endsWith(suffix))) return false;
  return true;
}

/** Resolves A and AAAA records with Cloudflare's DNS over HTTPS JSON API. */
export const resolveWithDoH: ResolveAddresses = async (hostname) => {
  const addresses: string[] = [];
  for (const type of ["A", "AAAA"] as const) {
    const url = new URL("https://cloudflare-dns.com/dns-query");
    url.searchParams.set("name", hostname);
    url.searchParams.set("type", type);
    const response = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(3000),
    });
    if (!response.ok) throw new Error(`DNS lookup failed with status ${response.status}`);
    const body = (await response.json()) as { Answer?: Array<{ type: number; data: string }> };
    for (const answer of body.Answer ?? []) {
      // 1 = A, 28 = AAAA. CNAME answers (5) are intermediate and skipped.
      if (answer.type === 1 || answer.type === 28) addresses.push(answer.data);
    }
  }
  return addresses;
};
