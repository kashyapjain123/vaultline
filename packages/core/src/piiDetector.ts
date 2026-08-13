/**
 * PII Detector
 *
 * Two complementary techniques, matching the two different shapes PII
 * takes in practice:
 *
 * 1. Structural regex — for identifiers that have a fixed, checkable
 *    format regardless of surrounding words (PAN, IFSC, email, SSN,
 *    Aadhaar). Credit card numbers get an extra Luhn checksum pass, since
 *    "any 13-19 digit run" alone is far too noisy.
 *
 * 2. Contextual number detection — for values that are JUST a number and
 *    only mean something sensitive next to the right keyword. "8080" is
 *    nothing on its own; "port 8080" and "he scored 8080 runs" have the
 *    identical number but only one is infrastructure detail. This reuses
 *    the same windowed-proximity idea as nlpProximityMatcher.ts, just
 *    with numeric value candidates instead of string value candidates.
 *
 * NOT implemented here: real named-entity recognition for person/org
 * names. That needs an actual NER model (spaCy, Presidio's default
 * pipeline, etc.) with downloaded weights — out of scope for a
 * dependency-free. A best-effort, clearly-experimental heuristic is
 * provided separately (see scanPersonNamesHeuristic) and is OFF by
 * default because its false-positive rate is high without real NER.
 */

import { Match, Severity, Category } from "./patternMatcher";
import { tokenize, trimPunct, cleanWord, isNumericToken, hasKeywordNear, luhnValid } from "./proximityUtils";

const CATEGORY: Category = "PII";

// --- Structural regex rules -------------------------------------------------

interface StructuralRule {
  id: string;
  label: string;
  severity: Severity;
  regex: RegExp;
  /** Optional extra validation beyond the regex shape (e.g. Luhn for cards). */
  validate?: (raw: string) => boolean;
}

const STRUCTURAL_RULES: StructuralRule[] = [
  {
    id: "email",
    label: "Email Address",
    severity: "low",
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
  {
    id: "pan-india",
    label: "PAN (India Tax ID)",
    severity: "high",
    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g,
  },
  {
    id: "ifsc-india",
    label: "IFSC (India Bank Branch Code)",
    severity: "medium",
    regex: /\b[A-Z]{4}0[A-Z0-9]{6}\b/g,
  },
  {
    id: "ssn-us",
    label: "SSN (US Social Security Number)",
    severity: "high",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    id: "credit-card",
    label: "Credit/Debit Card Number",
    severity: "high",
    regex: /\b\d(?:[ -]?\d){12,18}\b/g,
    validate: (raw) => luhnValid(raw.replace(/[ -]/g, "")),
  },
  {
    id: "amount-inr",
    label: "Currency Amount (INR)",
    severity: "medium",
    // Indian digit grouping is 2-2-3 (5,43,000), not the 3-3-3 used
    // elsewhere, so a plain \d{1,3}(,\d{3})* pattern would miss it.
    //
    // The UNGROUPED alternative matters just as much: the previous pattern
    // required the comma groups, so an INR prefix followed by six ungrouped
    // digits matched only the first two — truncating mid-number, which is
    // the worst possible outcome. It leaks the remaining digits AND corrupts
    // the text. The grouped form is listed first so the alternation prefers
    // it over a bare \d+ prefix.
    regex: /(?:₹|(?:Rs\.?|INR)\s?)\s?(?:\d{1,2}(?:,\d{2,3})+|\d+)(?:\.\d{1,2})?(?:\s?[kKmMbB])?\b/g,
  },
  {
    id: "amount-usd",
    label: "Currency Amount (USD)",
    severity: "medium",
    // Same two fixes as the INR rule above. The old pattern required 3-digit
    // comma grouping, so it truncated any ungrouped amount (a four-digit sum
    // with cents kept only the first three digits), and it had no suffix
    // handling, so a figure written with a k/m/b suffix dropped the suffix
    // and left it orphaned next to the placeholder — both wrong, and
    // obviously wrong to anyone reading the redacted text.
    regex: /\$\s?(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{1,2})?(?:\s?[kKmMbB])?\b/g,
  },
];

// Aadhaar (India national ID) is just 12 digits, usually grouped 4-4-4.
// That shape alone is too generic (matches lots of unrelated 12-digit
// runs), so require either the grouped-with-spaces format specifically,
// OR a nearby keyword ("aadhaar", "uid") if it's a bare unspaced run.
const AADHAAR_GROUPED = /\b\d{4}\s\d{4}\s\d{4}\b/g;
const AADHAAR_KEYWORDS = ["aadhaar", "aadhar", "uidai", "uid"];

export function scanPiiStructural(text: string): Match[] {
  const matches: Match[] = [];

  for (const rule of STRUCTURAL_RULES) {
    rule.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = rule.regex.exec(text)) !== null) {
      if (rule.validate && !rule.validate(m[0])) {
        if (m[0].length === 0) rule.regex.lastIndex++;
        continue;
      }
      matches.push({
        ruleId: rule.id,
        label: rule.label,
        severity: rule.severity,
        category: CATEGORY,
        value: m[0],
        start: m.index,
        end: m.index + m[0].length,
      });
      if (m[0].length === 0) rule.regex.lastIndex++;
    }
  }

  // Aadhaar, grouped format — trust the shape alone.
  AADHAAR_GROUPED.lastIndex = 0;
  let am: RegExpExecArray | null;
  while ((am = AADHAAR_GROUPED.exec(text)) !== null) {
    matches.push({
      ruleId: "aadhaar-india",
      label: "Aadhaar (India National ID)",
      severity: "high",
      category: CATEGORY,
      value: am[0],
      start: am.index,
      end: am.index + am[0].length,
    });
  }

  // Aadhaar, bare 12-digit run — only if a keyword is nearby.
  const tokens = tokenize(text);
  for (let i = 0; i < tokens.length; i++) {
    const digits = isNumericToken(tokens[i].text);
    if (!digits || digits.length !== 12) continue;
    if (!hasKeywordNear(tokens, i, AADHAAR_KEYWORDS, 4)) continue;
    matches.push({
      ruleId: "aadhaar-india-contextual",
      label: "Aadhaar (India National ID, contextual)",
      severity: "high",
      category: CATEGORY,
      value: digits,
      start: tokens[i].start,
      end: tokens[i].end,
    });
  }

  return matches;
}

// --- Contextual number detection --------------------------------------------

interface NumberContextGroup {
  category: string;
  label: string;
  severity: Severity;
  keywords: string[];
  minDigits: number;
  maxDigits: number;
}

const NUMBER_CONTEXT_GROUPS: NumberContextGroup[] = [
  {
    category: "phone",
    label: "Phone Number (contextual)",
    severity: "medium",
    keywords: ["phone", "mobile", "cell", "call", "contact", "tel", "telephone", "whatsapp"],
    minDigits: 7,
    maxDigits: 15,
  },
  {
    category: "account-number",
    label: "Account Number (contextual)",
    severity: "high",
    keywords: ["account", "acct", "a/c"],
    minDigits: 6,
    maxDigits: 18,
  },
  {
    category: "customer-id",
    label: "Customer/Employee/Order/Loan ID (contextual)",
    severity: "medium",
    keywords: ["customer", "employee", "order", "loan", "policy", "ticket", "case", "claim"],
    minDigits: 4,
    maxDigits: 15,
  },
];

const WINDOW = 4;

// --- Contextual alphanumeric government IDs ---------------------------------

/**
 * US passport and driver's license numbers are ALPHANUMERIC, so they can't
 * ride the numeric NUMBER_CONTEXT_GROUPS path above — isNumericToken()
 * rejects anything with a leading letter. They're also far too generic to
 * detect on shape alone ("A1234567" is indistinguishable from an order code
 * or a part number), so exactly like the numeric groups they only count when
 * the right keyword sits within a small token window.
 */
interface AlphanumericIdGroup {
  category: string;
  label: string;
  severity: Severity;
  keywords: string[];
  /** Tested against the punctuation-trimmed, uppercased token. */
  shape: RegExp;
}

const ALPHANUMERIC_ID_GROUPS: AlphanumericIdGroup[] = [
  {
    category: "passport-us",
    label: "US Passport Number (contextual)",
    severity: "high",
    keywords: ["passport", "passports"],
    // 9 digits (older books) or a letter followed by 8 digits (current ones).
    shape: /^(?:\d{9}|[A-Z]\d{8})$/,
  },
  {
    category: "drivers-license-us",
    label: "US Driver's License Number (contextual)",
    severity: "high",
    keywords: ["license", "licence", "licenses", "licences", "dl", "driver", "drivers", "driving"],
    // State formats vary far too much to encode all 50; this covers the
    // common letter+digits and all-digit shapes.
    shape: /^(?:[A-Z]\d{6,8}|\d{7,9})$/,
  },
];

const ALPHANUMERIC_ID_WINDOW = 4;

function scanAlphanumericIds(text: string): Match[] {
  const tokens = tokenize(text);
  const matches: Match[] = [];
  const claimed = new Set<number>(); // value-token indices already taken

  for (let i = 0; i < tokens.length; i++) {
    const w = cleanWord(tokens[i].text);
    for (const group of ALPHANUMERIC_ID_GROUPS) {
      if (!group.keywords.includes(w)) continue;

      const lo = Math.max(0, i - ALPHANUMERIC_ID_WINDOW);
      const hi = Math.min(tokens.length - 1, i + ALPHANUMERIC_ID_WINDOW);
      for (let j = lo; j <= hi; j++) {
        if (j === i || claimed.has(j)) continue;

        const raw = tokens[j].text;
        const clean = trimPunct(raw);
        if (!group.shape.test(clean.toUpperCase())) continue;

        claimed.add(j);
        // Offset by where the trimmed value actually starts, so stripped
        // leading punctuation doesn't shift the redaction span.
        const offset = raw.indexOf(clean);
        matches.push({
          ruleId: `contextual-${group.category}`,
          label: group.label,
          severity: group.severity,
          category: CATEGORY,
          value: clean,
          start: tokens[j].start + offset,
          end: tokens[j].start + offset + clean.length,
        });
        break; // one ID per keyword occurrence
      }
    }
  }

  return matches;
}

export function scanPiiContextual(text: string): Match[] {
  const tokens = tokenize(text);
  const matches: Match[] = [...scanAlphanumericIds(text)];
  const claimedPairs = new Set<string>(); // `${category}:${valueIdx}` to avoid dup if two keywords in same group hit the same number

  for (let i = 0; i < tokens.length; i++) {
    const w = cleanWord(tokens[i].text);
    for (const group of NUMBER_CONTEXT_GROUPS) {
      if (!group.keywords.includes(w)) continue;

      const lo = Math.max(0, i - WINDOW);
      const hi = Math.min(tokens.length - 1, i + WINDOW);
      for (let j = lo; j <= hi; j++) {
        if (j === i) continue;
        const digits = isNumericToken(tokens[j].text);
        if (!digits) continue;
        if (digits.length < group.minDigits || digits.length > group.maxDigits) continue;

        const key = `${group.category}:${j}`;
        if (claimedPairs.has(key)) continue;
        claimedPairs.add(key);

        matches.push({
          ruleId: `contextual-${group.category}`,
          label: group.label,
          severity: group.severity,
          category: CATEGORY,
          value: digits,
          start: tokens[j].start,
          end: tokens[j].end,
        });
      }
    }
  }

  return matches;
}

// --- Optional, experimental: heuristic person-name detection ---------------

// Deliberately small denylist of capitalized words that are common enough
// in ordinary English to cause noise if flagged as a "name". This is NOT a
// substitute for real NER — it's a coarse, opt-in heuristic only.
const CAPITALIZED_COMMON_WORDS = new Set([
  "The", "This", "That", "These", "Those", "Please", "Thanks", "Hello", "Hi",
  "January", "February", "March", "April", "May", "June", "July", "August",
  "September", "October", "November", "December", "Monday", "Tuesday",
  "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
]);

/**
 * Flags two-consecutive-Capitalized-Words as a possible person name.
 * OFF by default (see extension.ts config) — genuinely high false-positive
 * rate (product names, place names, book titles, sentence-initial capitals
 * all look identical to this heuristic). Ship only if you've validated the
 * false-positive rate against real usage, or replace with an actual NER
 * model.
 */
export function scanPersonNamesHeuristic(text: string): Match[] {
  const tokens = tokenize(text);
  const matches: Match[] = [];
  const nameRe = /^[A-Z][a-z]+$/;

  for (let i = 0; i < tokens.length - 1; i++) {
    const a = trimPunct(tokens[i].text);
    const b = trimPunct(tokens[i + 1].text);
    if (!nameRe.test(a) || !nameRe.test(b)) continue;
    if (CAPITALIZED_COMMON_WORDS.has(a) || CAPITALIZED_COMMON_WORDS.has(b)) continue;

    matches.push({
      ruleId: "heuristic-person-name",
      label: "Possible Person Name (heuristic, experimental)",
      severity: "low",
      category: CATEGORY,
      value: `${a} ${b}`,
      start: tokens[i].start,
      end: tokens[i + 1].end,
    });
  }

  return matches;
}

export interface PiiScanOptions {
  enablePersonNameHeuristic?: boolean;
}

export function scanPii(text: string, options: PiiScanOptions = {}): Match[] {
  const matches = [...scanPiiStructural(text), ...scanPiiContextual(text)];
  if (options.enablePersonNameHeuristic) {
    matches.push(...scanPersonNamesHeuristic(text));
  }
  return matches.sort((a, b) => a.start - b.start);
}
