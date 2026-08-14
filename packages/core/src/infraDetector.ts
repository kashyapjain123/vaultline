/**
 * Infrastructure Detector
 *
 * Catches internal-infrastructure details that aren't personal data but
 * still shouldn't leave the machine: IP addresses, internal URLs, file
 * paths, internal hostnames, and port numbers. Same split as piiDetector:
 * structural regex where the shape alone is enough signal (IPs, file
 * paths), context-proximity where a bare token is ambiguous on its own
 * (a hostname-shaped word, a port number that could just as easily be a
 * sports score).
 */

import { Match, Severity, Category } from "./patternMatcher";
import { tokenize, trimPunct, cleanWord, isNumericToken, hasKeywordNear } from "./proximityUtils";

const CATEGORY: Category = "INFRA";

const PRIVATE_IP = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/;
const ANY_IP = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
// Backslash excluded deliberately, on top of whitespace/quotes/angle
// brackets: a real URL never legitimately ends in one, but a literal
// backslash shows up right after a URL surprisingly often in text that was
// copy-pasted from somewhere JSON-escaped — a raw JSON source string
// represents an embedded newline as the two literal characters \ and n,
// and without this exclusion the regex happily swallows that escape
// sequence as if it were part of the URL's path (e.g. capturing
// "...api/getToken\n" — backslash-n, not a real line break — as the
// matched value), which then faithfully round-trips through
// tokenize/restore as that same corrupted value. Excluding backslash makes
// the match stop cleanly at the URL's real end in both cases.
// The backtick in the exclusion set is load-bearing: without it a template
// literal like `https://${host}/api`; matched straight through the closing
// backtick and the semicolon, so redacting it replaced working syntax rather
// than a value.
const URL_RE = /\bhttps?:\/\/[^\s"'`<>\\]+/g;
const UNIX_PATH = /(?<![\w])\/(?:[\w.-]+\/)+[\w.-]*/g;
const WIN_PATH = /\b[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]*/g;

// Top-level directory names that actually exist on a real macOS/Linux
// filesystem. This is the discriminator between "a real absolute path on
// THIS machine" and "a repo-relative path or URL-ish fragment someone
// typed in chat" — the two are syntactically identical ("/src/index.ts"
// vs "/etc/passwd"), so shape alone can't separate them, but the root
// segment can: there is no "/src" or "/components" on a real box, while
// "/etc" and "/Users" always exist.
//
// This narrowing matters specifically because this extension targets
// CODING agents: normal coding conversation is full of "./scripts/build.sh"
// and "/src/index.ts", none of which reveal anything about the developer's
// machine, and flagging every one of them was pure noise that trained
// people to ignore the redaction notice. What genuinely leaks is a real
// filesystem location — "/Users/<username>/..." exposes the OS account
// name, "/opt/acme-internal/..." exposes deployment layout — and those all
// start at one of these roots.
//
// Same reasoning as NON_SENSITIVE_IPV4 above: the goal is to flag what
// reveals something about THIS machine, not everything that merely
// matches the shape.
const REAL_FS_ROOTS = new Set([
  // Shared Unix roots
  "etc", "var", "usr", "opt", "srv", "mnt", "media", "tmp", "bin", "sbin",
  "lib", "lib64", "dev", "proc", "sys", "boot", "run", "home", "root",
  // macOS-specific
  "Users", "Applications", "Library", "System", "Volumes", "private", "cores",
]);

// Roots whose SECOND segment is a per-user identifier, so the path leaks
// an account name rather than just a directory layout. Used only to pick a
// more specific label — the rule ID stays the same so existing
// vaultline.disabledInfraRules configs keep working.
const HOME_ROOTS = new Set(["Users", "home", "root"]);

/**
 * Roots under which a path says something about THIS machine or THIS
 * organisation, and is therefore worth redacting.
 *
 * REAL_FS_ROOTS above answers a different question — "is this a filesystem
 * location at all, or a repo-relative fragment like /src/index.ts" — and it
 * still has to be broad for that. But recognising a path is not the same as it
 * being sensitive: `/dev/null`, `/usr/bin/python` and `/etc/nginx/nginx.conf`
 * are byte-identical on every machine on earth. Redacting them cost the model
 * useful context and revealed nothing in return.
 *
 * What remains is the two kinds that genuinely leak:
 *   - account names — /Users/<name>, /home/<name>, /root
 *   - product, project and share names — /opt/acme-payments/config.yml and
 *     /Volumes/AcmeShare/finance say as much about an organisation as an
 *     account name says about a person.
 */
const IDENTIFYING_ROOTS = new Set(["Users", "home", "root", "opt", "srv", "Volumes", "mnt", "media"]);

/** True when a recognised filesystem path is one worth redacting — see IDENTIFYING_ROOTS. */
function isIdentifyingPath(path: string): boolean {
  const segments = path.split("/");
  const firstSegment = segments[1] ?? "";
  if (!IDENTIFYING_ROOTS.has(firstSegment)) return false;
  // "/root" is itself an account's home directory, so it needs nothing after
  // it. Every other root here only identifies something once a second segment
  // names the user, product or volume — a bare "/opt" or "/Volumes" is generic.
  return firstSegment === "root" || (segments[2] ?? "").length > 0;
}

/**
 * True if this looks like a real filesystem location on a real machine,
 * rather than a repo-relative path or a URL-ish fragment.
 *
 * `precededByDot` covers the explicitly-relative forms: UNIX_PATH's
 * lookbehind only excludes a preceding word character, so "./etc/foo" and
 * "../etc/foo" both still match starting at their "/" — the leading dot(s)
 * sit just outside the match. Without checking for them, a relative
 * "./etc/nginx.conf" would be indistinguishable from a real "/etc/nginx.conf".
 * A relative path describes a location inside the project the agent is
 * already working in, which reveals nothing the conversation didn't
 * already contain.
 */
function isRealUnixPath(path: string, precededByDot: boolean): boolean {
  if (precededByDot) return false; // "./etc/foo", "../lib/x"
  const firstSegment = path.split("/")[1] ?? "";
  return REAL_FS_ROOTS.has(firstSegment);
}

function isHomeDirectoryPath(path: string): boolean {
  const segments = path.split("/");
  const firstSegment = segments[1] ?? "";
  if (!HOME_ROOTS.has(firstSegment)) return false;
  // "/root" is itself the root account's home; "/Users" and "/home" need a
  // following account-name segment to actually name a user.
  return firstSegment === "root" || (segments[2] ?? "").length > 0;
}
const MAC_ADDRESS = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g;
// Loose candidate: any maximal run of hex digits and colons, length >= 2.
// Self-delimiting (stops at the first non-hex/non-colon character), so no
// \b needed — which matters here, since \b doesn't behave usefully right
// before a leading ':' in a compressed address like '::1'. All the real
// validation (must be 8 groups, or contain exactly one valid '::'
// compression) happens in isValidIpv6() below; this regex is deliberately
// permissive so it can't accidentally truncate a real address the way a
// more "precise"-looking two-alternative regex did (that version silently
// dropped the leading group in 'fe80::...', matching only '::...').
const IPV6_CANDIDATE = /[0-9A-Fa-f:]{2,}/g;

// Values that are technically IP-shaped but carry essentially zero
// information on their own — universal constants (loopback, unspecified)
// or one of the 32 standard subnet masks. Flagging these is pure noise:
// every network has a 255.255.255.0 somewhere, and it reveals nothing
// about THIS network the way an actual host or broadcast address does.
const NON_SENSITIVE_IPV4 = new Set([
  "127.0.0.1", "0.0.0.0",
  "255.255.255.255", "255.255.255.254", "255.255.255.252", "255.255.255.248",
  "255.255.255.240", "255.255.255.224", "255.255.255.192", "255.255.255.128",
  "255.255.255.0", "255.255.0.0", "255.0.0.0",
]);
const NON_SENSITIVE_IPV6 = new Set(["::1", "::"]);

const INTERNAL_HOST_HINTS = new Set(["internal", "corp", "intranet", "lan", "vpn", "svc", "cluster"]);

function isInternalHost(host: string): boolean {
  if (PRIVATE_IP.test(host)) return true;
  const lower = host.toLowerCase();
  if (lower.endsWith(".local") || lower.endsWith(".internal")) return true;

  // Whole hostname PARTS, not substrings. An unanchored `includes()` here
  // classified a pile of ordinary public hosts as internal (at medium
  // severity): "atlanta.example.com" contains "lan", "corporate-blog.com"
  // contains "corp", "incorporated.com" contains both, "milan.it" contains
  // "lan", "clustering.io" contains "cluster". Splitting on '.', '-' and '_'
  // still catches every real internal form — internal-api.company.com,
  // api.corp.acme.com, svc.cluster.local, prod-db.internal, vpn.acme.com.
  return lower.split(/[.\-_]/).some((part) => INTERNAL_HOST_HINTS.has(part));
}

// Hosts that resolve to the developer's own machine. A URL pointing at one
// of these describes THIS process, not any real deployment — it reveals
// nothing about the network, exactly like the loopback entries already
// excluded from NON_SENSITIVE_IPV4/IPV6 above ("every network has a
// 127.0.0.1"). Local dev URLs are everywhere in a coding workflow —
// package.json scripts, README setup steps, test config, this extension's own
// default embedding endpoint — so flagging them was pure noise in the one
// context this tool is aimed at.
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "host.docker.internal"]);

function isLoopbackHost(host: string): boolean {
  const lower = host.toLowerCase();
  if (LOOPBACK_HOSTS.has(lower)) return true;
  if (lower.startsWith("127.")) return true; // the whole 127.x/8 loopback range
  return lower.endsWith(".localhost"); // RFC 6761 reserves *.localhost for loopback too
}

/**
 * Trailing characters that punctuate the surrounding sentence or code rather
 * than belong to the value.
 *
 * A URL or path regex matches greedily up to whitespace, so it happily absorbs
 * whatever ends the sentence: `https://host/docs)` from a markdown link,
 * `https://host.` from prose, `/etc/nginx/nginx.conf.`, `C:\...\app.log,`.
 * Redacting those replaces the punctuation too, which corrupts the text around
 * the value it was supposed to protect.
 *
 * The closing-bracket rule is the subtle half. A trailing `)` is only noise
 * when it has no opener INSIDE the value — `…/wiki/Foo_(bar)` is a genuine URL
 * whose parenthesis is part of the path, and stripping it would produce a
 * broken link. Counting first is what separates the two.
 */
function trimTrailingNoise(value: string): string {
  const PAIRS: Record<string, string> = { ")": "(", "]": "[", "}": "{" };
  let end = value.length;

  while (end > 0) {
    const ch = value[end - 1];
    if (".,;:!?'\"".includes(ch)) {
      end--;
      continue;
    }
    const opener = PAIRS[ch];
    if (opener) {
      const inner = value.slice(0, end);
      const opens = inner.split(opener).length - 1;
      const closes = inner.split(ch).length - 1;
      if (closes > opens) {
        end--;
        continue;
      }
    }
    break;
  }

  return value.slice(0, end);
}

function scanUrls(text: string): { matches: Match[]; spans: Array<[number, number]> } {
  const matches: Match[] = [];
  const spans: Array<[number, number]> = [];
  URL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = URL_RE.exec(text)) !== null) {
    // ALWAYS claim the full raw span, before any trimming — scanIps and
    // scanFilePaths consult these to avoid separately re-flagging a URL's host
    // or path portion, and that suppression must still cover the parts we
    // decline to redact ourselves.
    spans.push([m.index, m.index + m[0].length]);

    // Truncate at a template interpolation. Truncate, NOT skip: skipping any
    // URL containing `${` would silently stop redacting
    // `https://svc-01.corp.example.internal/${path}` — leaking exactly the
    // internal hostname this rule exists to catch. Cutting at the `${` keeps
    // the literal prefix (and its host) and drops the expression.
    const interpolation = m[0].indexOf("${");
    const truncated = interpolation === -1 ? m[0] : m[0].slice(0, interpolation);
    const value = trimTrailingNoise(truncated);

    // Nothing left worth redacting: a bare `https://` is what remains of a URL
    // built entirely from `${…}` expressions, which contains no hostname at all.
    // Redacting it would replace code and protect nothing.
    if (!/^https?:\/\/\S/i.test(value)) continue;

    let host = "";
    let url: URL | null = null;
    try {
      url = new URL(value);
      host = url.hostname;
    } catch {
      // Malformed URL — still worth flagging at low confidence (unchanged
      // behaviour), just with no host analysis. The guard above already
      // established there IS an authority here, so this is a real if unparsable
      // URL rather than a leftover scheme.
    }

    if (host && isLoopbackHost(host)) continue;

    // Redact the AUTHORITY only — hostname plus port — and leave the path in
    // clear.
    //
    // The host is what's actually sensitive: it reveals internal naming,
    // environment and topology. A path like /api/getToken is generic REST
    // vocabulary that rarely reveals anything, and is exactly what a code
    // assistant needs in order to write a working client. Tokenising the whole
    // URL hid both, so the model could not produce a correct call and got
    // nothing back in exchange for the loss.
    //
    // Falls back to the whole match when the authority can't be located (an
    // unparsable URL, where `host` is empty) — over-redacting, which is the
    // safe direction.
    const authority = host ? (url?.port ? `${host}:${url.port}` : host) : "";
    const authorityAt = authority ? value.indexOf(authority) : -1;
    const redactStart = authorityAt >= 0 ? m.index + authorityAt : m.index;
    const redactValue = authorityAt >= 0 ? authority : value;

    const internal = host ? isInternalHost(host) : false;
    matches.push({
      ruleId: internal ? "internal-url" : "external-url",
      label: internal ? "Internal URL Host" : "URL Host",
      severity: internal ? "medium" : "low",
      category: CATEGORY,
      value: redactValue,
      start: redactStart,
      end: redactStart + redactValue.length,
    });
  }
  return { matches, spans };
}

function overlapsAny(start: number, end: number, spans: Array<[number, number]>): boolean {
  return spans.some(([s, e]) => start < e && end > s);
}

function scanFilePaths(text: string, excludeSpans: Array<[number, number]>): Match[] {
  const matches: Match[] = [];

  UNIX_PATH.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = UNIX_PATH.exec(text)) !== null) {
    // Trim BEFORE the checks below, so "/etc/nginx/nginx.conf." is judged (and
    // redacted) as the path it is rather than the path plus the full stop that
    // ended the sentence.
    const value = trimTrailingNoise(m[0]);
    if (value.length < 4) continue; // skip trivial single-segment noise
    if (overlapsAny(m.index, m.index + value.length, excludeSpans)) continue; // don't double-count a URL's path portion
    const precededByDot = m.index > 0 && text[m.index - 1] === ".";
    if (!isRealUnixPath(value, precededByDot)) continue; // repo-relative / URL-ish fragment — see isRealUnixPath
    if (!isIdentifyingPath(value)) continue; // real, but universal — /dev/null tells nobody anything
    const isHome = isHomeDirectoryPath(value);
    matches.push({
      ruleId: "unix-file-path",
      label: isHome ? "File Path (home directory — exposes account name)" : "File Path",
      severity: "low",
      category: CATEGORY,
      value,
      start: m.index,
      end: m.index + value.length,
    });
  }

  // No equivalent narrowing needed here: a Windows match always carries a
  // drive letter ("C:\..."), so it's inherently a real absolute location —
  // there's no relative/repo-fragment ambiguity to resolve the way there is
  // for a bare-slash Unix path.
  WIN_PATH.lastIndex = 0;
  while ((m = WIN_PATH.exec(text)) !== null) {
    const value = trimTrailingNoise(m[0]);
    if (value.length === 0) continue;
    const isHome = /^[A-Za-z]:\\Users\\[^\\]+/i.test(value);
    matches.push({
      ruleId: "windows-file-path",
      label: isHome ? "File Path (home directory — exposes account name)" : "File Path",
      severity: "low",
      category: CATEGORY,
      value,
      start: m.index,
      end: m.index + value.length,
    });
  }

  return matches;
}

function scanIps(text: string, excludeSpans: Array<[number, number]>): Match[] {
  const matches: Match[] = [];
  ANY_IP.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ANY_IP.exec(text)) !== null) {
    if (overlapsAny(m.index, m.index + m[0].length, excludeSpans)) continue; // already counted as part of a URL host
    if (NON_SENSITIVE_IPV4.has(m[0])) continue; // loopback, unspecified, or a standard netmask — no real signal
    const isPrivate = PRIVATE_IP.test(m[0]);
    matches.push({
      ruleId: isPrivate ? "private-ip-standalone" : "public-ip-standalone",
      label: isPrivate ? "Internal IP Address" : "IP Address",
      severity: isPrivate ? "medium" : "low",
      category: CATEGORY,
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
    });
  }
  return matches;
}

function scanMacAddresses(text: string): { matches: Match[]; spans: Array<[number, number]> } {
  const matches: Match[] = [];
  const spans: Array<[number, number]> = [];
  MAC_ADDRESS.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = MAC_ADDRESS.exec(text)) !== null) {
    spans.push([m.index, m.index + m[0].length]);
    matches.push({
      ruleId: "mac-address",
      label: "MAC Address",
      severity: "medium",
      category: CATEGORY,
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
    });
  }
  return { matches, spans };
}

/**
 * A MAC address (6 groups of exactly 2 hex digits, no "::" compression) is
 * NOT a valid IPv6 form, so this rejects it as a side effect of validating
 * proper IPv6 shape — no separate MAC-exclusion check needed here, though
 * excludeSpans (MAC spans) is still passed in as a belt-and-suspenders
 * guard in case a malformed edge case slips past the shape check.
 */
function isValidIpv6(candidate: string): boolean {
  if (candidate.includes("::")) {
    const parts = candidate.split("::");
    if (parts.length !== 2) return false;
    const left = parts[0] ? parts[0].split(":").filter(Boolean) : [];
    const right = parts[1] ? parts[1].split(":").filter(Boolean) : [];
    const total = left.length + right.length;
    if (total > 7) return false; // "::" must represent at least one omitted group
    return [...left, ...right].every((g) => /^[0-9A-Fa-f]{1,4}$/.test(g));
  }
  const groups = candidate.split(":").filter(Boolean);
  if (groups.length !== 8) return false; // uncompressed IPv6 always has exactly 8 groups
  return groups.every((g) => /^[0-9A-Fa-f]{1,4}$/.test(g));
}

/** Number of hex groups in a candidate, ignoring the "::" compression gap. */
function ipv6GroupCount(candidate: string): number {
  return candidate.split(/::?/).filter(Boolean).length;
}

function scanIpv6(text: string, excludeSpans: Array<[number, number]>): Match[] {
  const matches: Match[] = [];
  IPV6_CANDIDATE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = IPV6_CANDIDATE.exec(text)) !== null) {
    if (!m[0].includes(":")) continue; // not colon-based at all — plain hex run, not a candidate
    if (overlapsAny(m.index, m.index + m[0].length, excludeSpans)) continue;
    if (!isValidIpv6(m[0])) continue;
    if (NON_SENSITIVE_IPV6.has(m[0])) continue; // loopback / unspecified

    // --- Guards against SCOPE-RESOLUTION OPERATORS in source code ---------
    //
    // isValidIpv6() alone is far too permissive in a coding context, because
    // a single hex letter beside "::" is a technically-valid compressed
    // address: "e::" really is 000e::. That made this rule fire on ordinary
    // code in every language with a :: operator —
    //   std::vector    -> "d::"      Foo::bar()      -> "::ba"
    //   std::cout      -> "d::c"     self::CONSTANT  -> "f::C"
    //   entityType::value -> "e::"   (this file's own sibling module)
    // which silently punched placeholders into source the model was reading,
    // and cost it real reasoning budget (it reported one as a "corrupted
    // comment" bug that did not exist).
    //
    // Three cheap conditions remove that entire class while keeping every
    // real address — verified against both short and full link-local forms,
    // a compressed global address, and a full 8-group literal.

    // 1. Not a fragment of a longer identifier. A real address is delimited
    //    by whitespace/punctuation; "d::" in "std::vector" is preceded by
    //    't' and followed by 'v'.
    const before = text[m.index - 1] ?? "";
    const after = text[m.index + m[0].length] ?? "";
    if (/[A-Za-z0-9_]/.test(before) || /[A-Za-z0-9_]/.test(after)) continue;

    // 2. At least two groups. "e::" (one group) carries no address meaning;
    //    ::1 and :: are already excluded as non-sensitive above.
    if (ipv6GroupCount(m[0]) < 2) continue;

    // 3. Contains a digit. Real addresses effectively always do (fe80, 2001,
    //    db8, a00, 27ff); an all-letter "abc::def" is far more likely to be
    //    a namespace than an address.
    if (!/\d/.test(m[0])) continue;

    const isLinkLocal = m[0].toLowerCase().startsWith("fe80:");
    matches.push({
      ruleId: isLinkLocal ? "ipv6-link-local" : "ipv6-standalone",
      label: isLinkLocal ? "IPv6 Link-Local Address" : "IPv6 Address",
      severity: isLinkLocal ? "low" : "medium",
      category: CATEGORY,
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
    });
  }
  return matches;
}

// --- Hostname (contextual) --------------------------------------------------

const HOSTNAME_SHAPE = /^[a-z0-9]+(?:-[a-z0-9]+){1,4}$/i;
const HOSTNAME_CONTEXT_KEYWORDS = [
  "server", "host", "hostname", "db", "database", "node", "cluster",
  "instance", "machine", "box", "vm", "pod", "ssh", "deploy", "provision",
];
const HOSTNAME_WINDOW = 4;

function scanHostnames(text: string): Match[] {
  const tokens = tokenize(text);
  const matches: Match[] = [];

  for (let i = 0; i < tokens.length; i++) {
    const clean = trimPunct(tokens[i].text);
    if (!HOSTNAME_SHAPE.test(clean)) continue;
    if (!/\d/.test(clean)) continue; // require a digit — cuts down on ordinary hyphenated phrases
    if (!hasKeywordNear(tokens, i, HOSTNAME_CONTEXT_KEYWORDS, HOSTNAME_WINDOW)) continue;

    matches.push({
      ruleId: "internal-hostname-contextual",
      label: "Internal Hostname (contextual)",
      severity: "medium",
      category: CATEGORY,
      value: clean,
      start: tokens[i].start,
      end: tokens[i].start + clean.length,
    });
  }

  return matches;
}

// --- Port (contextual) ------------------------------------------------------

const PORT_KEYWORDS = ["port"];
const PORT_WINDOW = 3;

function scanPorts(text: string): Match[] {
  const tokens = tokenize(text);
  const matches: Match[] = [];

  for (let i = 0; i < tokens.length; i++) {
    if (!PORT_KEYWORDS.includes(cleanWord(tokens[i].text))) continue;

    const lo = Math.max(0, i - PORT_WINDOW);
    const hi = Math.min(tokens.length - 1, i + PORT_WINDOW);
    for (let j = lo; j <= hi; j++) {
      if (j === i) continue;
      const digits = isNumericToken(tokens[j].text);
      if (!digits) continue;
      const value = parseInt(digits, 10);
      if (value < 1 || value > 65535) continue;

      matches.push({
        ruleId: "port-contextual",
        label: "Port Number (contextual)",
        severity: "low",
        category: CATEGORY,
        value: digits,
        start: tokens[j].start,
        end: tokens[j].end,
      });
      break; // one hit per "port" mention
    }
  }

  return matches;
}

export function scanInfraStructural(text: string): Match[] {
  const { matches: urlMatches, spans: urlSpans } = scanUrls(text);
  const { matches: macMatches, spans: macSpans } = scanMacAddresses(text);
  const excludeSpans = [...urlSpans, ...macSpans];
  const pathMatches = scanFilePaths(text, excludeSpans);
  const ipMatches = scanIps(text, excludeSpans);
  const ipv6Matches = scanIpv6(text, excludeSpans);

  return [...urlMatches, ...macMatches, ...pathMatches, ...ipMatches, ...ipv6Matches].sort(
    (a, b) => a.start - b.start
  );
}

export function scanInfraContextual(text: string): Match[] {
  const hostnameMatches = scanHostnames(text);
  const portMatches = scanPorts(text);
  return [...hostnameMatches, ...portMatches].sort((a, b) => a.start - b.start);
}

export function scanInfra(text: string): Match[] {
  return [...scanInfraStructural(text), ...scanInfraContextual(text)].sort((a, b) => a.start - b.start);
}
